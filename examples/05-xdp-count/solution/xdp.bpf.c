//go:build ignore

/*
 * 05. XDP - 네트워크 스택 최전선에서 패킷 보기
 *
 * XDP 프로그램은 드라이버가 패킷을 받은 직후, skb 가 만들어지기도 전에
 * 실행된다. Cilium 의 로드밸런싱/DDoS 드롭이 여기서 일어난다.
 *
 * 이 예제는 판단하지 않고 세기만 한다 (항상 XDP_PASS).
 * 반환값으로 XDP_DROP / XDP_TX / XDP_REDIRECT 를 주면 패킷 운명이 바뀐다.
 *
 * veth(컨테이너 eth0) 에는 native XDP 가 없을 수 있으므로 Go 쪽에서
 * generic(SKB) 모드로 붙인다.
 *
 * 포인터 산술 주의: data / data_end 로 매 접근 전 경계를 검사하지 않으면
 * verifier 가 로드를 거부한다. eBPF 안전성의 핵심 부분이다.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806

/* key: IP 프로토콜 번호(6=TCP, 17=UDP, 1=ICMP).
 * 256=ARP, 257=IPv6(상세 파싱 생략), 258=기타로 몰아 넣는다. */
#define SLOT_ARP 256
#define SLOT_IPV6 257
#define SLOT_OTHER 258
#define SLOT_MAX 259

struct proto_stat {
	__u64 packets;
	__u64 bytes;
};

struct proto_stat *unused_proto_stat __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct proto_stat);
	__uint(max_entries, SLOT_MAX);
} proto_stats SEC(".maps");

static __always_inline void count(__u32 slot, __u64 len)
{
	struct proto_stat *s = bpf_map_lookup_elem(&proto_stats, &slot);
	if (!s)
		return;
	s->packets++;
	s->bytes += len;
}

SEC("xdp")
int xdp_count(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 len = data_end - data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) /* 경계 검사 필수 */
		return XDP_PASS;

	__u16 proto = bpf_ntohs(eth->h_proto);

	if (proto == ETH_P_ARP) {
		count(SLOT_ARP, len);
		return XDP_PASS;
	}
	if (proto == ETH_P_IPV6) {
		count(SLOT_IPV6, len);
		return XDP_PASS;
	}
	if (proto != ETH_P_IP) {
		count(SLOT_OTHER, len);
		return XDP_PASS;
	}

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	count(ip->protocol, len);
	return XDP_PASS;
}
