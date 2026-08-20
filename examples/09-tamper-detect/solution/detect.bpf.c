//go:build ignore

/*
 * 09. 변조 vs 탐지 (Red vs Blue) - 관측을 넘어 무결성 검사로
 *
 * 08번은 패킷을 바꿨다. 그런데 "바뀌었다"는 걸 어떻게 알아챌까?
 * 이 예제는 loopback 안에서 벌어지는 자가 검증 게임이다:
 *
 *   🔴 Red   = 08번 변조기 (egress 에서 TTL 이나 포트를 바꾼다)
 *   🔵 Blue  = 이 프로그램 (ingress 에서 "정상값과 다른" 패킷을 잡는다)
 *
 * loopback 은 egress 로 나간 패킷이 곧바로 ingress 로 들어온다. 그래서
 * 한 머신 안에서 "변조 -> 탐지"가 완결된다. 외부 대상은 전혀 없다.
 *
 * 탐지 원리는 실무 침입탐지(IDS)와 같다: "이 환경에서 당연히 성립해야 할
 * 불변식(invariant)"을 정해두고, 그게 깨지면 경보한다.
 *   - loopback 로컬 트래픽의 TTL 은 항상 64 여야 한다. 42 라면? 누가 건드렸다.
 *   - 우리가 아는 서비스 포트가 아니라면? 리다이렉트 의심.
 *   - 헤더의 IHL 이 말이 안 되면? 조작된 패킷.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TC_ACT_OK 0    /* vmlinux.h 에 없어서 직접 정의 */
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IP_OFF ETH_HLEN

/* 이 환경의 불변식 */
#define EXPECTED_TTL 64 /* loopback 로컬 트래픽의 정상 TTL */

/* 경보 종류 */
#define ALERT_TTL 1      /* TTL 이 기대값과 다르다 */
#define ALERT_BADHDR 2   /* IP 헤더가 말이 안 된다 */
#define ALERT_PORT 3     /* 허용되지 않은 목적지 포트 */

/* 통계 슬롯 */
#define STAT_SEEN 0     /* 검사한 IPv4 패킷 수 */
#define STAT_TTL 1      /* TTL 이상 */
#define STAT_BADHDR 2   /* 헤더 이상 */
#define STAT_PORT 3     /* 포트 이상 */
#define STAT_MAX 4

struct alert {
	__u64 ts;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 kind;      /* ALERT_* */
	__u8 got;       /* 실제로 관측된 값 (TTL 등) */
	__u8 expected;  /* 기대했던 값 */
	__u8 pad;
};

struct alert *unused_alert __attribute__((unused));

/* 탐지기 설정: 감시할 목적지 포트 (0 이면 포트 검사 끔) */
struct dconfig {
	__u16 watch_port; /* 이 포트로 오는 트래픽만 포트 정책 적용 */
	__u16 allow_port; /* 이 포트만 정상으로 본다 */
	__u8 check_ttl;   /* TTL 불변식 검사 on/off */
	__u8 pad[3];
};

struct dconfig *unused_dconfig __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct dconfig);
	__uint(max_entries, 1);
} dconfig_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} alerts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} dstats SEC(".maps");

static __always_inline void bump(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&dstats, &slot);
	if (v)
		(*v)++;
}

static __always_inline void raise_alert(struct __sk_buff *skb, __u32 ihl,
					__u8 kind, __u8 got, __u8 expected)
{
	struct alert *a = bpf_ringbuf_reserve(&alerts, sizeof(*a), 0);
	if (!a)
		return;
	a->ts = bpf_ktime_get_ns();
	a->kind = kind;
	a->got = got;
	a->expected = expected;
	a->pad = 0;
	a->sport = 0;
	a->dport = 0;
	bpf_skb_load_bytes(skb, IP_OFF + 12, &a->saddr, 4);
	bpf_skb_load_bytes(skb, IP_OFF + 16, &a->daddr, 4);

	__u8 proto = 0;
	bpf_skb_load_bytes(skb, IP_OFF + 9, &proto, 1);
	if (proto == 6 || proto == 17) { /* TCP/UDP 면 포트도 담는다 */
		__u32 l4 = IP_OFF + ihl;
		__u16 sp = 0, dp = 0;
		bpf_skb_load_bytes(skb, l4, &sp, 2);
		bpf_skb_load_bytes(skb, l4 + 2, &dp, 2);
		a->sport = bpf_ntohs(sp);
		a->dport = bpf_ntohs(dp);
	}
	bpf_ringbuf_submit(a, 0);
}

SEC("tc")
int detect_ingress(struct __sk_buff *skb)
{
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	__u32 z = 0;
	struct dconfig *cfg = bpf_map_lookup_elem(&dconfig_map, &z);
	if (!cfg)
		return TC_ACT_OK;

	__u8 vihl;
	if (bpf_skb_load_bytes(skb, IP_OFF, &vihl, 1) < 0)
		return TC_ACT_OK;

	/* 불변식 1: 헤더가 말이 되는가 */
	if ((vihl >> 4) != 4 || (vihl & 0x0f) < 5) {
		bump(STAT_BADHDR);
		raise_alert(skb, 5, ALERT_BADHDR, vihl, 0x45);
		return TC_ACT_OK;
	}
	__u32 ihl = (vihl & 0x0f) * 4;
	bump(STAT_SEEN);

	/* 불변식 2: loopback 로컬 트래픽의 TTL 은 64 여야 한다 */
	if (cfg->check_ttl) {
		__u8 ttl;
		if (bpf_skb_load_bytes(skb, IP_OFF + 8, &ttl, 1) == 0 &&
		    ttl != EXPECTED_TTL) {
			bump(STAT_TTL);
			raise_alert(skb, ihl, ALERT_TTL, ttl, EXPECTED_TTL);
		}
	}

	/* 불변식 3: 감시 대상 흐름은 허용된 포트로만 와야 한다 */
	if (cfg->watch_port) {
		__u8 proto = 0;
		bpf_skb_load_bytes(skb, IP_OFF + 9, &proto, 1);
		if (proto == 6) { /* TCP */
			__u16 dp = 0;
			bpf_skb_load_bytes(skb, IP_OFF + ihl + 2, &dp, 2);
			__u16 dport = bpf_ntohs(dp);
			/* watch_port 로 향하던 트래픽이 엉뚱한 포트로 바뀌었나?
			 * (08번 DNAT 가 목적지 포트를 바꾸면 여기 걸린다) */
			if (dport != cfg->allow_port && dport == cfg->watch_port) {
				/* 아직 정상: watch_port 그대로 */
			}
			if (dport != cfg->allow_port && dport != cfg->watch_port) {
				bump(STAT_PORT);
				raise_alert(skb, ihl, ALERT_PORT, 0, 0);
			}
		}
	}

	return TC_ACT_OK;
}
