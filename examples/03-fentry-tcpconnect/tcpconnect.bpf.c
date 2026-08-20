//go:build ignore

/*
 * 03. fentry / fexit - BTF 기반 함수 트레이싱 (Cilium 이 실제로 쓰는 방식)
 *
 * fentry/fexit 는 kprobe/kretprobe 의 현대적 대체품이다.
 *   - BPF 트램폴린을 함수 진입부에 직접 심어서 kprobe(브레이크포인트)보다 빠르다
 *   - BTF 로 함수 시그니처를 알기 때문에 인자를 struct sock * 처럼 타입으로 받는다
 *     -> 인자 개수/타입이 틀리면 로드 시점에 verifier 가 거부한다
 *   - fexit 는 kretprobe 와 달리 "진입 인자 + 반환값"을 동시에 볼 수 있다
 *
 * 필요 조건: CONFIG_DEBUG_INFO_BTF=y, CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
 *            (make check 로 확인 가능)
 *
 * 대상: net/ipv4/tcp_output.c 의 int tcp_connect(struct sock *sk)
 *       -> TCP 3-way handshake 의 SYN 을 보내기 직전에 호출된다
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

/* 통계 슬롯 */
#define STAT_CALLS 0
#define STAT_FAILED 1
#define STAT_IPV6 2
#define STAT_MAX 3

struct event {
	__u32 tgid;
	__u32 saddr; /* 네트워크 바이트 오더 그대로 */
	__u32 daddr;
	__u16 sport; /* 호스트 오더 */
	__u16 dport; /* 호스트 오더 */
	__u8 comm[TASK_COMM_LEN];
};

struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

static __always_inline void bump(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v)
		(*v)++;
}

/* ---- fentry: 함수 진입. 인자를 타입 그대로 받는다 ---- */
SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect_entry, struct sock *sk)
{
	bump(STAT_CALLS);

	/* struct sock 의 공통 헤더(struct sock_common)에서 주소/포트를 읽는다.
	 * BPF_CORE_READ 는 -> 를 연쇄로 따라가며 CO-RE 재배치를 걸어준다. */
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET) {
		if (family == AF_INET6)
			bump(STAT_IPV6);
		return 0;
	}

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	/* skc_num(로컬 포트)은 호스트 오더, skc_dport(원격 포트)는 네트워크 오더 */
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- fexit: 함수 반환. 진입 인자 + 반환값을 함께 받는다 ----
 * kretprobe 로는 sk 를 다시 보려면 진입 시점에 맵에 저장해 뒀어야 한다. */
SEC("fexit/tcp_connect")
int BPF_PROG(tcp_connect_exit, struct sock *sk, int ret)
{
	if (ret != 0)
		bump(STAT_FAILED);
	return 0;
}
