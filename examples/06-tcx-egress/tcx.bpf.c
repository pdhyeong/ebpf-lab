//go:build ignore

/*
 * 06. TCX - 현대 Cilium 의 데이터패스 진입점        [🎯 실습 랩 — 빈칸을 채운다]
 *
 * 예전 Cilium 은 tc(traffic control) clsact qdisc 에 BPF 필터를 붙였다.
 * 커널 6.6 부터는 TCX 라는 전용 링크 타입이 생겨서, netlink 로 qdisc 를
 * 만들 필요 없이 bpf_link 로 ingress/egress 에 프로그램을 붙일 수 있다.
 * (여러 프로그램을 순서대로 체이닝하는 것도 커널이 관리해 준다)
 *
 * XDP 와의 차이:
 *   XDP    : skb 생성 전, ingress 만, 아주 빠름, 헤더 조작 제약이 있음
 *   TC/TCX : skb 가 있는 상태, ingress + egress 둘 다, 메타데이터가 풍부함
 *
 * ┌─ 진행 방법 ──────────────────────────────────────────────────────┐
 * │  make 06          지금 상태로 실행 (전부 0 으로 나온다)           │
 * │  Lv1 → Lv2 → Lv3 순서로 TODO 를 채운다                            │
 * │  make 06-check    단계별 자동 채점                                │
 * │  막히면           solution/tcx.bpf.c                              │
 * └──────────────────────────────────────────────────────────────────┘
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

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv1 [35점] — 방향별 패킷/바이트를 세어라
	 *
	 *   PERCPU 맵이라 원자 연산이 필요 없다. 그냥 증가시키면 된다.
	 *
	 *   할 일:
	 *       s->packets++;
	 *       s->bytes += skb->len;
	 *
	 *   ✅ 통과 조건: ping 을 치면 INGRESS 의 PACKETS/BYTES 가 올라간다
	 *   💡 skb->len 은 XDP 의 (data_end - data) 와 달리 커널이 이미 계산해
	 *      놓은 값이다. TC 컨텍스트가 메타데이터가 풍부하다는 게 이런 의미다.
	 * ══════════════════════════════════════════════════════════════════ */
	/* TODO(Lv1) */

	/* skb->protocol 은 호스트 오더가 아니라 네트워크 오더로 들어온다. */
	if (bpf_ntohs(skb->protocol) != ETH_P_IP)
		return TCX_NEXT;

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv2 [25점] — IPv4 프로토콜별로 분류하라
	 *
	 *   XDP 처럼 포인터를 직접 만지지 않는다. TC 컨텍스트에서는
	 *   bpf_skb_load_bytes() 로 안전하게 읽는 게 관용구다.
	 *   (skb 는 조각나 있을 수 있어서 직접 포인터 접근이 위험하다)
	 *
	 *   L2 헤더 14바이트 다음이 IP 헤더이고, protocol 필드는 그 안에서 +9.
	 *
	 *   할 일:
	 *       __u8 ipproto = 0;
	 *       if (bpf_skb_load_bytes(skb, 14 + 9, &ipproto, sizeof(ipproto)) < 0)
	 *               return TCX_NEXT;
	 *       switch (ipproto) {
	 *       case 1:  s->icmp++; break;   // ICMP
	 *       case 6:  s->tcp++;  break;   // TCP
	 *       case 17: s->udp++;  break;   // UDP
	 *       }
	 *
	 *   ✅ 통과 조건: ping 후 ICMP 칸이, TCP 연결 후 TCP 칸이 올라간다
	 * ══════════════════════════════════════════════════════════════════ */
	/* TODO(Lv2) */

	return TCX_NEXT;
}

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv0 [10점] — 어디에 붙을지 직접 찾아라
	 *
	 *   훅 선택이 eBPF 개발의 8할이다. 정답을 받아적는 게 아니라
	 *   찾는 절차를 손에 익히는 게 이 단계의 목적이다.
	 *
	 *   여기서는 "함수 찾기" 가 아니라 "어느 훅 계층인가" 를 고른다.
	 *
	 *   ① 나가는(egress) 트래픽을 봐야 한다. XDP 로 되나?
	 *      -> XDP 는 ingress 전용이다. 안 된다.
	 *
	 *   ② 그럼 어느 계층인가?
	 *      skb 가 있는 계층 = TC. 커널 6.6+ 는 TCX 로 붙인다.
	 *      uname -r        # 6.6 이상인지 확인
	 *
	 *   ③ 이 커널이 지원하는 프로그램 타입 목록
	 *      bpftool feature probe | grep -i sched
	 *      -> sched_cls (= TC classifier) 가 우리가 쓸 타입이다
	 *
	 *   형식:  SEC("tc")   — 짧다. cilium/ebpf 가 이걸 sched_cls 로 매핑한다.
	 *
	 *   ✅ 통과 조건: 프로그램이 "부착 완료" 를 출력한다
	 *   ⚠️  지금은 SEC("TODO") 라서 로드 자체가 실패한다:
	 *      "program type is unspecified"
	 *      섹션 이름이 곧 프로그램 타입이기 때문이다.
	 * ══════════════════════════════════════════════════════════════════ */
SEC("TODO")
int tcx_ingress(struct __sk_buff *skb)
{
	return account(skb, DIR_INGRESS);
}

SEC("TODO") /* TODO(Lv0): 위와 같다 */
int tcx_egress(struct __sk_buff *skb)
{
	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv3 [15점] — 나가는 방향도 세어라
	 *
	 *   TCX 가 XDP 와 다른 결정적 지점이다. XDP 는 ingress 밖에 없다.
	 *   같은 account() 를 방향만 바꿔 부르면 된다.
	 *
	 *   할 일:  return account(skb, DIR_EGRESS);
	 *
	 *   ✅ 통과 조건: EGRESS 행의 PACKETS 가 0 이 아니다
	 *   💡 loopback 에서는 나간 패킷이 곧바로 들어온다. 그래서 ping 하나로
	 *      ingress/egress 가 동시에 올라간다 (09/14번 게임이 이걸 이용한다).
	 * ══════════════════════════════════════════════════════════════════ */
	return TCX_NEXT; /* TODO(Lv3) */
}

/*
 * 🏆 Lv4 [10점] — 특정 포트만 세기 (보너스)
 *
 *   TCP 헤더까지 읽어 목적지 포트가 특정 값일 때만 카운트하라.
 *   힌트: bpf_skb_load_bytes(skb, 14 + 20 + 2, &dport, 2) 후 bpf_ntohs.
 *         (IP 헤더 길이를 20 으로 가정하는 건 옵션이 없을 때만 맞다 — IHL 확인이 정석)
 *   ✅ 통과 조건: 소스에 포트 로드와 비교가 있다
 */
