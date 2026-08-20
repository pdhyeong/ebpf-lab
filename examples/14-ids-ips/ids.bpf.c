//go:build ignore

/*
 * 14. IDS/IPS 게임 (게임판 - TODO 를 채워라) - 시그니처 기반 침입 탐지·차단
 *
 * Snort/Suricata 같은 IDS/IPS 의 핵심은 "패킷 내용에서 알려진 공격 시그니처를
 * 찾는 것"이다. 이 예제는 그 축소판을 TC 훅에서 한다: UDP 페이로드에 악성
 * 시그니처("EVIL")가 들어있으면
 *   - IDS 모드: 경보만 올리고 통과 (탐지)
 *   - IPS 모드: 아예 떨군다 (차단)
 *
 * IDS 는 "탐지", IPS 는 "차단"이다. 같은 엔진에 모드 스위치 하나 차이.
 * 실무에서 IPS 를 인라인으로 걸면 오탐 하나가 정상 트래픽을 끊으므로,
 * 보통 IDS 로 한참 관찰한 뒤에야 IPS 로 승격한다.
 *
 * loopback 안에서: nc -u 로 "EVIL" 이 든 데이터그램을 보내면
 *   IDS -> 서버는 받고, 경보도 뜬다
 *   IPS -> 서버가 못 받는다 (커널이 떨궜다)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define IP_OFF ETH_HLEN
#define SCAN_LEN 40 /* 페이로드 앞 40바이트만 스캔 */

#define MODE_IDS 0
#define MODE_IPS 1

struct iconfig {
	__u32 mode; /* 0=IDS(경보), 1=IPS(차단) */
};

struct iconfig *unused_iconfig __attribute__((unused));

struct alert {
	__u64 ts;
	__u32 saddr;
	__u16 dport;
	__u8 blocked; /* IPS 로 차단했으면 1 */
	__u8 pad;
};

struct alert *unused_alert __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct iconfig);
	__uint(max_entries, 1);
} iconfig_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} ialerts SEC(".maps");

/* [0]=검사한 UDP, [1]=시그니처 매치, [2]=IPS 차단 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 3);
} istats SEC(".maps");

static __always_inline void bump(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&istats, &i);
	if (v)
		(*v)++;
}

/* payload 앞부분에서 "EVIL" 을 찾는다. verifier 때문에 상한은 상수여야 한다. */
/* payload 앞부분에서 "EVIL" 을 찾는다.
 * 각 위치에서 4바이트(상수 크기)씩 읽어 비교한다. 크기가 상수라
 * verifier 의 zero-sized read 문제를 피한다. skb->len 으로 경계도 지킨다. */
static __always_inline int match_sig(struct __sk_buff *skb, __u32 off)
{
	__u32 len = skb->len;
#pragma unroll
	for (int i = 0; i < SCAN_LEN - 4; i++) {
		__u32 pos = off + i;
		if (pos + 4 > len)
			break;
		char w[4];
		if (bpf_skb_load_bytes(skb, pos, w, 4) < 0)
			break;
		if (w[0] == 'E' && w[1] == 'V' && w[2] == 'I' && w[3] == 'L')
			return 1;
	}
	return 0;
}

SEC("tc")
int ids_ingress(struct __sk_buff *skb)
{
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	__u8 vihl;
	if (bpf_skb_load_bytes(skb, IP_OFF, &vihl, 1) < 0)
		return TC_ACT_OK;
	if ((vihl >> 4) != 4)
		return TC_ACT_OK;
	__u32 ihl = (vihl & 0x0f) * 4;

	__u8 proto;
	if (bpf_skb_load_bytes(skb, IP_OFF + 9, &proto, 1) < 0)
		return TC_ACT_OK;
	if (proto != IPPROTO_UDP)
		return TC_ACT_OK;

	bump(0); /* 검사한 UDP (이건 이미 세어 준다) */

	__u32 udp_off = IP_OFF + ihl;
	__u32 payload_off = udp_off + 8; /* UDP 헤더 8바이트 뒤가 페이로드 */

	/* ==================================================================
	 * TODO - 시그니처를 찾고, 모드에 따라 탐지/차단하라.
	 *
	 *   1) if (!match_sig(skb, payload_off)) return TC_ACT_OK;
	 *      (match_sig 는 위에 이미 구현돼 있다. "EVIL" 을 찾는다)
	 *
	 *   2) bump(1);  // 시그니처 매치 카운트
	 *
	 *   3) 모드 읽기:
	 *      struct iconfig *cfg = bpf_map_lookup_elem(&iconfig_map, &(__u32){0});
	 *      __u8 blocked = (cfg && cfg->mode == MODE_IPS) ? 1 : 0;
	 *
	 *   4) 경보 올리기(ringbuf) - solution 참고해서 alert 채우기.
	 *
	 *   5) if (blocked) { bump(2); return TC_ACT_SHOT; }  // IPS: 차단
	 *      else          return TC_ACT_OK;                // IDS: 탐지만
	 *
	 *   막히면 solution/ids.bpf.c 참고.
	 *
	 *   💡 확장 아이디어(직접): 시그니처 여러 개(맵에 등록), TCP 도 검사,
	 *      정규식 대신 여러 키워드, 매치 위치/횟수 기록 등.
	 * ================================================================== */

	return TC_ACT_OK; /* 지금은 전부 통과 (아무것도 안 잡는다) */
}
