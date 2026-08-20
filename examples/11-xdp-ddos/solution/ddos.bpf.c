//go:build ignore

/*
 * 11. XDP DDoS 방어 게임 (정답본) - 드라이버 최전선에서 공격을 떨군다
 *
 * XDP 는 skb 가 만들어지기도 전, 드라이버가 패킷을 받은 그 순간 실행된다.
 * 그래서 DDoS 를 여기서 떨구면 커널이 소켓 버퍼도, conntrack 도 안 만든다.
 * Cloudflare/Cilium 이 대용량 공격을 흡수하는 바로 그 지점이다.
 *
 * 게임: SYN flood 탐지·차단.
 *   - 공격자는 SYN 을 초당 수천 개 퍼붓는다 (핸드셰이크를 완성 안 함).
 *   - 출발지 IP 별로 "1초에 SYN 몇 개"를 세고, 임계값을 넘으면 XDP_DROP.
 *   - 정상 트래픽(가끔 오는 SYN)은 통과(XDP_PASS).
 *
 * 핵심 자료구조: LRU 해시맵. 출발지 IP 가 키. 오래된 항목은 자동 축출되므로
 * 무한히 많은 IP 가 와도 맵이 터지지 않는다 (DDoS 는 IP 가 많다).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define TH_SYN 0x02
#define TH_ACK 0x10

#define NS_PER_SEC 1000000000ULL

/* 튜닝 파라미터 (유저 공간에서 config 로 주입) */
struct dconfig {
	__u32 syn_per_sec; /* 초당 이 개수를 넘는 출발지는 차단 */
};

struct dconfig *unused_dconfig __attribute__((unused));

struct rate {
	__u64 window_start; /* 현재 1초 창의 시작 (ns) */
	__u32 syn_count;    /* 이 창에서 온 SYN 수 */
	__u32 blocked;      /* 차단 상태 여부 */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct dconfig);
	__uint(max_entries, 1);
} config_map SEC(".maps");

/* 출발지 IP -> 속도 상태. LRU 라 공격 IP 가 아무리 많아도 안전. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);   /* saddr */
	__type(value, struct rate);
	__uint(max_entries, 1 << 16);
} rates SEC(".maps");

/* 통계: [0]=검사한 SYN, [1]=차단(DROP)한 SYN */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
} xstats SEC(".maps");

static __always_inline void bump(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&xstats, &i);
	if (v)
		(*v)++;
}

SEC("xdp")
int ddos_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	__u32 ihl = ip->ihl * 4;
	if (ihl < sizeof(*ip))
		return XDP_PASS;

	struct tcphdr *tcp = (void *)ip + ihl;
	if ((void *)(tcp + 1) > data_end)
		return XDP_PASS;

	/* SYN 이면서 ACK 아님 = 새 커넥션 요청 (핸드셰이크 1단계) */
	__u8 flags = ((__u8 *)tcp)[13];
	if (!(flags & TH_SYN) || (flags & TH_ACK))
		return XDP_PASS;

	bump(0); /* 검사한 SYN */

	__u32 z = 0;
	struct dconfig *cfg = bpf_map_lookup_elem(&config_map, &z);
	if (!cfg || cfg->syn_per_sec == 0)
		return XDP_PASS;

	__u32 saddr = ip->saddr;
	__u64 now = bpf_ktime_get_ns();

	struct rate *r = bpf_map_lookup_elem(&rates, &saddr);
	if (!r) {
		struct rate init = {.window_start = now, .syn_count = 1, .blocked = 0};
		bpf_map_update_elem(&rates, &saddr, &init, BPF_ANY);
		return XDP_PASS;
	}

	/* 1초 창이 지났으면 리셋 */
	if (now - r->window_start >= NS_PER_SEC) {
		r->window_start = now;
		r->syn_count = 1;
		r->blocked = 0;
		return XDP_PASS;
	}

	r->syn_count++;

	/* 임계값 초과 = 이 출발지는 공격자. 이 창 동안 SYN 을 떨군다. */
	if (r->syn_count > cfg->syn_per_sec) {
		r->blocked = 1;
		bump(1); /* 차단 */
		return XDP_DROP;
	}

	return XDP_PASS;
}
