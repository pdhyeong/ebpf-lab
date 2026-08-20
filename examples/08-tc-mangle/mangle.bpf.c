//go:build ignore

/*
 * 08. TC 패킷 변조 (mangle) - "읽기"에서 "쓰기"로
 *
 * 05(XDP)/06(TCX)은 패킷을 세기만 했다. 여기서는 실제로 고쳐서 내보낸다.
 * 전부 내 loopback 안에서, 내 패킷을 내가 바꾸는 학습용이다.
 *
 * 패킷 변조의 진짜 난관은 체크섬이다. IP/TCP 헤더에서 1바이트만 바꿔도
 * 체크섬이 깨지면 커널이 그 패킷을 조용히 버린다. "코드는 맞는데 통신이
 * 안 되는" 상황이 여기서 나온다. 그래서 bpf_skb_store_bytes 로 값을 쓴 뒤
 * 반드시 bpf_l3/l4_csum_replace 로 체크섬을 증분 재계산해야 한다.
 *
 * 실측 결과(README 참고): loopback 도 14바이트 이더넷 헤더를 가진다
 * (단, MAC 이 전부 0). 그래서 eth0 과 동일하게 IP 헤더는 offset 14 다.
 *
 * 동작은 config 맵으로 런타임에 고른다(재컴파일 없음):
 *   TTL   - IP TTL 을 지정 값으로 (L3 체크섬만)
 *   DSCP  - IP TOS/DSCP 마킹 (L3 체크섬만)
 *   DNAT  - TCP 목적지 포트 재작성 (L4 체크섬만) <- 가장 깔끔한 예
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TC_ACT_OK 0    /* vmlinux.h 에 없어서 직접 정의 */
#define TC_ACT_SHOT 2
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

/* IP/TCP 헤더 내 필드 오프셋 (표준 헤더 기준) */
#define IP_OFF ETH_HLEN
#define IP_TOS_OFF (IP_OFF + 1)
#define IP_TTL_OFF (IP_OFF + 8)
#define IP_CSUM_OFF (IP_OFF + 10)
#define IP_DADDR_OFF (IP_OFF + 16)

/* 동작 종류 */
#define ACT_OFF 0
#define ACT_TTL 1
#define ACT_DSCP 2
#define ACT_DNAT 3

struct config {
	__u32 action;
	__u8 ttl;        /* ACT_TTL: 새 TTL */
	__u8 dscp;       /* ACT_DSCP: 새 DSCP (하위 6비트) */
	__u16 match_port; /* ACT_DNAT: 이 목적지 포트를 (호스트 오더) */
	__u16 new_port;   /* ACT_DNAT: 이 포트로 바꾼다 (호스트 오더) */
};

struct config *unused_config __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct config);
	__uint(max_entries, 1);
} config_map SEC(".maps");

/* 몇 번 변조했는지 (검증용) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} rewrites SEC(".maps");

static __always_inline void bump(void)
{
	__u32 z = 0;
	__u64 *v = bpf_map_lookup_elem(&rewrites, &z);
	if (v)
		(*v)++;
}

SEC("tc")
int mangle_egress(struct __sk_buff *skb)
{
	__u32 z = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &z);
	if (!cfg || cfg->action == ACT_OFF)
		return TC_ACT_OK;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* IP 헤더의 version/IHL 과 protocol 을 읽는다.
	 * bpf_skb_load_bytes 는 커널이 경계를 대신 검사해 준다 (XDP 와 다른 점). */
	__u8 vihl;
	if (bpf_skb_load_bytes(skb, IP_OFF, &vihl, 1) < 0)
		return TC_ACT_OK;
	if ((vihl >> 4) != 4) /* IPv4 만 */
		return TC_ACT_OK;
	__u32 ihl = (vihl & 0x0f) * 4; /* IP 헤더 길이 (가변) */

	switch (cfg->action) {
	case ACT_TTL: {
		__u8 old_ttl;
		if (bpf_skb_load_bytes(skb, IP_TTL_OFF, &old_ttl, 1) < 0)
			return TC_ACT_OK;
		if (old_ttl == cfg->ttl)
			return TC_ACT_OK;
		/* TTL 은 [ttl, protocol] 16비트 워드의 상위 바이트다.
		 * 체크섬 증분 계산은 이 16비트 워드 단위로 한다. */
		__u8 proto;
		if (bpf_skb_load_bytes(skb, IP_TTL_OFF + 1, &proto, 1) < 0)
			return TC_ACT_OK;
		__u16 old_word = bpf_htons((old_ttl << 8) | proto);
		__u16 new_word = bpf_htons((cfg->ttl << 8) | proto);
		bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_word, new_word, 2);
		bpf_skb_store_bytes(skb, IP_TTL_OFF, &cfg->ttl, 1, 0);
		bump();
		break;
	}
	case ACT_DSCP: {
		__u8 old_tos;
		if (bpf_skb_load_bytes(skb, IP_TOS_OFF, &old_tos, 1) < 0)
			return TC_ACT_OK;
		/* DSCP 는 TOS 바이트의 상위 6비트. ECN(하위 2비트)은 보존. */
		__u8 new_tos = (cfg->dscp << 2) | (old_tos & 0x03);
		if (old_tos == new_tos)
			return TC_ACT_OK;
		/* TOS 는 [version/ihl, tos] 워드의 하위 바이트다. */
		__u16 old_word = bpf_htons((vihl << 8) | old_tos);
		__u16 new_word = bpf_htons((vihl << 8) | new_tos);
		bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_word, new_word, 2);
		bpf_skb_store_bytes(skb, IP_TOS_OFF, &new_tos, 1, 0);
		bump();
		break;
	}
	case ACT_DNAT: {
		__u8 proto;
		if (bpf_skb_load_bytes(skb, IP_OFF + 9, &proto, 1) < 0)
			return TC_ACT_OK;
		if (proto != IPPROTO_TCP)
			return TC_ACT_OK;

		__u32 tcp_off = IP_OFF + ihl;
		__u16 sport_be, dport_be;
		if (bpf_skb_load_bytes(skb, tcp_off, &sport_be, 2) < 0)
			return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, tcp_off + 2, &dport_be, 2) < 0)
			return TC_ACT_OK;

		__u16 match_be = bpf_htons(cfg->match_port);
		__u16 new_be = bpf_htons(cfg->new_port);

		/* 포트는 IP 헤더에 없으므로 IP 체크섬은 안 건드린다. TCP(L4)만.
		 * tcphdr: sport=+0, dport=+2, check=+16 */
		if (dport_be == match_be) {
			/* 정방향: 클라이언트 -> 서버. 목적지 포트를 바꾼다. */
			bpf_l4_csum_replace(skb, tcp_off + 16, dport_be, new_be, 2);
			bpf_skb_store_bytes(skb, tcp_off + 2, &new_be, 2, 0);
			bump();
		} else if (sport_be == new_be) {
			/* 역방향: 서버 -> 클라이언트. 출발지 포트를 원래대로 되돌린다.
			 * 이 되돌림이 없으면 클라이언트가 "내가 접속한 8080 이 아닌
			 * 9090 에서 온 응답"이라며 커넥션을 거부한다. 실제 NAT 가
			 * conntrack 으로 상태를 추적하는 이유가 바로 이것이다. */
			bpf_l4_csum_replace(skb, tcp_off + 16, sport_be, match_be, 2);
			bpf_skb_store_bytes(skb, tcp_off, &match_be, 2, 0);
			bump();
		}
		break;
	}
	}

	return TC_ACT_OK;
}
