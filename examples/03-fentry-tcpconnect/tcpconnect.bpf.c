//go:build ignore

/*
 * 03. fentry / fexit - BTF 기반 함수 트레이싱       [🎯 실습 랩 — 빈칸을 채운다]
 *                      (Cilium / Tetragon 이 실제로 쓰는 방식)
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
 *
 * ┌─ 진행 방법 ──────────────────────────────────────────────────────┐
 * │  make 03          지금 상태로 실행 (이벤트가 안 나온다)           │
 * │  Lv1 → Lv2 → Lv3 순서로 TODO 를 채운다                            │
 * │  make 03-check    단계별 자동 채점                                │
 * │  막히면           solution/tcpconnect.bpf.c                       │
 * └──────────────────────────────────────────────────────────────────┘
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

/* 통계 슬롯 하나를 1 증가시킨다 (PERCPU 라 원자 연산 불필요) */
static __always_inline __attribute__((unused)) void bump(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v)
		(*v)++;
}

/* ---- fentry: 함수 진입. 인자를 타입 그대로 받는다 ---- */
	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv0 [10점] — 어디에 붙을지 직접 찾아라
	 *
	 *   훅 선택이 eBPF 개발의 8할이다. 정답을 받아적는 게 아니라
	 *   찾는 절차를 손에 익히는 게 이 단계의 목적이다.
	 *
	 *   ① tracepoint 가 있나?
	 *      ls /sys/kernel/debug/tracing/events/ | grep -i tcp
	 *      -> tcp/ 그룹은 있지만 "연결 시도" 지점은 없다. 다음 단계로.
	 *
	 *   ② BTF 에 그 함수가 있나? (bpftrace 0.20 은 fentry 를 kfunc 라 부른다)
	 *      bpftrace -l 'kfunc:*tcp_connect*'
	 *
	 *   ③ 시그니처를 확인한다 — fentry 는 틀리면 로드가 거부된다
	 *      bpftool btf dump file /sys/kernel/btf/vmlinux format c \
	 *        | grep -w 'tcp_connect'
	 *      -> int tcp_connect(struct sock *sk)
	 *
	 *   형식:  SEC("fentry/<함수이름>")   진입
	 *          SEC("fexit/<함수이름>")    반환 (아래 함수도 채워야 한다)
	 *
	 *   ✅ 통과 조건: 프로그램이 "부착 완료" 를 출력한다
	 *   ⚠️  지금은 SEC("TODO") 라서 로드 자체가 실패한다:
	 *      "program type is unspecified"
	 *      섹션 이름이 곧 프로그램 타입이기 때문이다.
	 * ══════════════════════════════════════════════════════════════════ */
SEC("fentry/TODO")
int BPF_PROG(tcp_connect_entry, struct sock *sk)
{
	__u16 family;

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv1 [30점] — 호출을 세고 이벤트를 올려라
	 *
	 *   fentry 는 kprobe 와 달리 sk 를 이미 "struct sock *" 타입으로 준다.
	 *   pt_regs 에서 인자를 파내는 작업이 없다 — 이게 fentry 의 편의성이다.
	 *
	 *   할 일 (1) 호출 카운트:
	 *       bump(STAT_CALLS);
	 *
	 *   할 일 (2) family 를 읽어 IPv4 만 이벤트로 올린다:
	 *       family = BPF_CORE_READ(sk, __sk_common.skc_family);
	 *
	 *   할 일 (3) 아래 e = NULL; 을 링버퍼 예약으로 교체:
	 *       e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	 *
	 *   ✅ 통과 조건: TCP 연결을 시도하면 이벤트 행이 찍히고 누적이 올라간다
	 *   💡 왜 BPF_CORE_READ 인가? sk->__sk_common.skc_family 로 직접 읽으면
	 *      빌드 당시 오프셋이 그대로 박힌다. CO-RE 재배치가 걸리지 않는다.
	 * ══════════════════════════════════════════════════════════════════ */
	/* TODO(Lv1): bump(STAT_CALLS); */

	family = AF_INET; /* TODO(Lv1): BPF_CORE_READ 로 실제 family 읽기 */

	if (family != AF_INET) {
		/* ══════════════════════════════════════════════════════════
		 * 🎯 Lv3 [20점] — IPv6 는 따로 세어라
		 *
		 *   IPv4 가 아니면 이벤트는 안 올리되, IPv6 였다는 사실은 남긴다.
		 *   "안 보이는 트래픽이 있다"는 걸 아는 게 관측의 기본이다.
		 *
		 *   할 일:
		 *       if (family == AF_INET6)
		 *               bump(STAT_IPV6);
		 *
		 *   ✅ 통과 조건: ::1 로 연결 시도하면 누적 줄의 IPv6 가 올라간다
		 * ══════════════════════════════════════════════════════════ */
		/* TODO(Lv3) */
		return 0;
	}

	struct event *e;
	e = NULL; /* TODO(Lv1) */
	if (!e)
		return 0;

	e->tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv2 [25점] — 주소와 포트를 CO-RE 로 읽어라
	 *
	 *   struct sock 의 공통 헤더(struct sock_common)에 다 들어 있다.
	 *   바이트 오더가 필드마다 다른 게 함정이다:
	 *       skc_num   (로컬 포트)  = 호스트 오더  -> 변환 불필요
	 *       skc_dport (원격 포트)  = 네트워크 오더 -> bpf_ntohs 필요
	 *       skc_*addr (주소)       = 네트워크 오더 -> Go 쪽에서 변환한다
	 *
	 *   할 일:
	 *       e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	 *       e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	 *       e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	 *       e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	 *
	 *   ✅ 통과 조건: DST 칸에 실제 목적지 IP:포트가 정확히 찍힌다
	 *   💡 bpf_ntohs 를 빼면 포트가 엉뚱한 큰 숫자로 나온다. 오더 실수는
	 *      네트워크 eBPF 에서 가장 흔한 버그다.
	 * ══════════════════════════════════════════════════════════════════ */
	e->saddr = 0; /* TODO(Lv2) */
	e->daddr = 0; /* TODO(Lv2) */
	e->sport = 0; /* TODO(Lv2) */
	e->dport = 0; /* TODO(Lv2) */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- fexit: 함수 반환. 진입 인자 + 반환값을 함께 받는다 ----
 * kretprobe 로는 sk 를 다시 보려면 진입 시점에 맵에 저장해 뒀어야 한다.
 * fexit 는 그 저장/회수 과정이 통째로 사라진다. */
SEC("fexit/TODO") /* TODO(Lv0): 위와 같은 함수 */
int BPF_PROG(tcp_connect_exit, struct sock *sk, int ret)
{
	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv3 (같이) — 반환값으로 실패를 세어라
	 *
	 *   할 일:
	 *       if (ret != 0)
	 *               bump(STAT_FAILED);
	 *
	 *   💡 fexit 의 마지막 인자가 반환값이다. 이게 kretprobe 와의 결정적 차이:
	 *      진입 인자(sk)와 반환값(ret)을 한 자리에서 동시에 볼 수 있다.
	 * ══════════════════════════════════════════════════════════════════ */
	/* TODO(Lv3) */
	return 0;
}

/*
 * 🏆 Lv4 [10점] — 커널 단계 포트 필터 (보너스)
 *
 *   지금은 모든 TCP 연결이 유저 공간까지 올라온다. 특정 포트만 보고 싶다면
 *   커널에서 걸러야 한다.
 *
 *   힌트: dport 를 먼저 계산해서 관심 포트가 아니면 reserve 하기 전에 return 0.
 *         이미 예약했다면 bpf_ringbuf_discard(e, 0) 로 버린다.
 */
