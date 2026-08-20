//go:build ignore

/*
 * 06. TCX - 현대 Cilium 의 데이터패스 진입점
 *
 * 예전 Cilium 은 tc(traffic control) clsact qdisc 에 BPF 필터를 붙였다.
 * 커널 6.6 부터는 TCX 라는 전용 링크 타입이 생겨서, netlink 로 qdisc 를
 * 만들 필요 없이 bpf_link 로 ingress/egress 에 프로그램을 붙일 수 있다.
 * (여러 프로그램을 순서대로 체이닝하는 것도 커널이 관리해 준다)
 *
 * XDP 와의 차이:
 *   XDP : skb 생성 전, ingress 만, 아주 빠름, 헤더 조작 제약이 있음
 *   TC/TCX : skb 가 있는 상태, ingress + egress 둘 다, 메타데이터가 풍부함
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/* TCX 반환값: 다음 프로그램으로 넘긴다(체인 계속). vmlinux.h 에 없어서 직접 정의. */
#define TCX_NEXT -1
#define TC_ACT_OK 0

#define DIR_INGRESS 0
#define DIR_EGRESS 1
#define DIR_MAX 2

#define ETH_P_IP 0x0800

struct dir_stat {
	__u64 packets;
	__u64 bytes;
	__u64 tcp;
	__u64 udp;
	__u64 icmp;
};

struct dir_stat *unused_dir_stat __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct dir_stat);
	__uint(max_entries, DIR_MAX);
} dir_stats SEC(".maps");

static __always_inline int account(struct __sk_buff *skb, __u32 dir)
{
	struct dir_stat *s = bpf_map_lookup_elem(&dir_stats, &dir);
	if (!s)
		return TCX_NEXT;

	s->packets++;
	s->bytes += skb->len;

	/* skb->protocol 은 호스트 오더가 아니라 네트워크 오더로 들어온다. */
	if (bpf_ntohs(skb->protocol) != ETH_P_IP)
		return TCX_NEXT;

	/* TC 컨텍스트에서는 bpf_skb_load_bytes 로 페이로드를 안전하게 읽는다.
	 * L2 헤더 14바이트 다음이 IP 헤더이고, protocol 필드는 그 안에서 +9. */
	__u8 ipproto = 0;
	if (bpf_skb_load_bytes(skb, 14 + 9, &ipproto, sizeof(ipproto)) < 0)
		return TCX_NEXT;

	switch (ipproto) {
	case 1:
		s->icmp++;
		break;
	case 6:
		s->tcp++;
		break;
	case 17:
		s->udp++;
		break;
	}
	return TCX_NEXT;
}

SEC("tc")
int tcx_ingress(struct __sk_buff *skb)
{
	return account(skb, DIR_INGRESS);
}

SEC("tc")
int tcx_egress(struct __sk_buff *skb)
{
	return account(skb, DIR_EGRESS);
}
