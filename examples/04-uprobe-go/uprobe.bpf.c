//go:build ignore

/*
 * 04. uprobe - 유저 공간 함수 트레이싱 (Go 바이너리)  [🎯 실습 랩 — 빈칸을 채운다]
 *
 * uprobe 는 ELF 파일의 오프셋에 트랩을 심는다. 커널이 아니라 우리가 만든
 * Go 프로그램의 함수를 잡는 것이다. 여기서는 target/workload 의
 *   func compute(n int) int
 * 진입점을 잡아 인자 n 을 읽는다.
 *
 * ── Frida 를 써 봤다면 여기가 가장 익숙한 예제다 ──
 *   Interceptor.attach(addr, { onEnter(args) { args[0] } })  ≈  이 파일
 *   차이는 (1) 커널이 트랩을 관리하고 (2) verifier 를 통과해야 하며
 *        (3) 대상 프로세스가 죽어도 훅은 파일 오프셋에 남아 있다는 점이다.
 *
 * Go 함수 인자 읽기 주의점:
 *   - Go 1.17+ 는 레지스터 기반 호출 규약(regabi)을 쓴다. arm64 에서 첫 정수
 *     인자는 X0, amd64 에서는 RAX 다. libbpf 의 BPF_UPROBE 매크로가
 *     아키텍처별로 알아서 맞는 레지스터를 골라준다.
 *   - uretprobe 는 Go 에서 쓰지 말 것. 고루틴 스택이 이동하면 uretprobe 가
 *     심어둔 복귀 주소가 무효화되어 대상 프로세스가 죽을 수 있다.
 *     반환값이 필요하면 "함수의 return 지점 오프셋에 uprobe" 를 붙인다.
 *
 * ┌─ 진행 방법 ──────────────────────────────────────────────────────┐
 * │  make 04          지금 상태로 실행 (이벤트가 안 나온다)           │
 * │  Lv1 → Lv2 → Lv3 순서로 TODO 를 채운다                            │
 * │  make 04-check    단계별 자동 채점                                │
 * │  막히면           solution/uprobe.bpf.c                           │
 * └──────────────────────────────────────────────────────────────────┘
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16

struct event {
	__u32 tgid;
	__u32 pid;
	__s64 arg; /* compute() 의 첫 번째 인자 */
	__u64 ts;  /* 부팅 후 나노초 */
	__u8 comm[TASK_COMM_LEN];
};

struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* SEC 이름의 "uprobe/..." 뒷부분은 라벨일 뿐이다. 실제 대상 파일/심볼은
 * 유저 공간(Go)에서 link.OpenExecutable(...).Uprobe("main.compute", ...) 로 정한다. */
	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv0 [10점] — 어디에 붙을지 직접 찾아라
	 *
	 *   훅 선택이 eBPF 개발의 8할이다. 정답을 받아적는 게 아니라
	 *   찾는 절차를 손에 익히는 게 이 단계의 목적이다.
	 *
	 *   uprobe 는 커널이 아니라 "파일의 심볼" 이 대상이다.
	 *
	 *   ① 대상 바이너리에 그 심볼이 실제로 있나?
	 *      go tool nm /opt/lab/bin/workload | grep main.compute
	 *      -> 없다면 스트립됐거나 인라인된 것 (//go:noinline 으로 막는다)
	 *
	 *   ② C/C++ 바이너리라면
	 *      nm -D /usr/lib/libssl.so | grep SSL_write
	 *
	 *   ③ 이 파일이 uprobe 를 걸 수 있는 파일시스템에 있나?
	 *      /lab (virtiofs) 위의 파일에는 못 붙는다. make workload 로
	 *      /opt/lab/bin 에 빌드하는 이유다.
	 *
	 *   형식:  SEC("uprobe/<아무 라벨>")
	 *          뒷부분은 라벨일 뿐 실제 대상은 Go 쪽에서 정한다.
	 *          하지만 앞의 "uprobe" 는 프로그램 타입이라 정확해야 한다.
	 *
	 *   ✅ 통과 조건: 프로그램이 "부착 완료" 를 출력한다
	 *   ⚠️  지금은 SEC("TODO") 라서 로드 자체가 실패한다:
	 *      "program type is unspecified"
	 *      섹션 이름이 곧 프로그램 타입이기 때문이다.
	 * ══════════════════════════════════════════════════════════════════ */
SEC("TODO")
int BPF_UPROBE(uprobe_compute, long n)
{
	struct event *e;

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv1 [30점] — 링버퍼 예약
	 *
	 *   할 일:  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	 *
	 *   ✅ 통과 조건: workload 가 도는 동안 이벤트 행이 찍힌다
	 *   💡 uprobe 는 대상 프로세스의 컨텍스트에서 실행된다. 그래서
	 *      bpf_get_current_comm() 이 "workload" 를 돌려준다.
	 * ══════════════════════════════════════════════════════════════════ */
	e = NULL; /* TODO(Lv1) */

	if (!e)
		return 0;

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv2 [25점] — 누가 언제 불렀는지
	 *
	 *   할 일:
	 *       __u64 id = bpf_get_current_pid_tgid();
	 *       e->tgid = id >> 32;
	 *       e->pid  = (__u32)id;
	 *       e->ts   = bpf_ktime_get_ns();
	 *       bpf_get_current_comm(&e->comm, sizeof(e->comm));
	 *
	 *   ✅ 통과 조건: COMM 칸에 workload 가 찍힌다
	 *   💡 bpf_ktime_get_ns() 는 부팅 기준 단조 시각이다. 벽시계가 아니다.
	 *      main.go 가 부팅 시각을 더해서 사람이 읽는 시간으로 바꾼다.
	 * ══════════════════════════════════════════════════════════════════ */
	e->tgid = 0;    /* TODO(Lv2) */
	e->pid = 0;     /* TODO(Lv2) */
	e->ts = 0;      /* TODO(Lv2) */
	e->comm[0] = 0; /* TODO(Lv2) */

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv3 [20점] — 함수 인자를 읽어라
	 *
	 *   BPF_UPROBE 매크로가 이미 n 을 인자로 뽑아 놨다. 그대로 담으면 된다.
	 *
	 *   할 일:  e->arg = n;
	 *
	 *   ✅ 통과 조건: ARG(n) 칸이 0 이 아닌 실제 값으로 찍힌다
	 *   💡 이 한 줄이 되는 이유가 중요하다. BPF_UPROBE 는 내부적으로
	 *      PT_REGS_PARM1(ctx) 를 쓰고, 그게 arm64 에서는 X0, x86_64 에서는
	 *      RAX 로 확장된다. 아키텍처를 신경 쓰지 않아도 되는 이유다.
	 *      Go 1.16 이하(스택 기반 호출 규약)였다면 이 방법이 통하지 않는다.
	 * ══════════════════════════════════════════════════════════════════ */
	e->arg = 0; /* TODO(Lv3) */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * 🏆 Lv4 [10점] — 인자 기반 필터 (보너스)
 *
 *   "n 이 특정 값 이상일 때만" 이벤트를 올려라. 커널 안에서 걸러야
 *   유저 공간 비용이 안 든다.
 *
 *   힌트: reserve 전에 if (n < 임계값) return 0; 을 넣는 게 제일 싸다.
 *         이미 예약했다면 bpf_ringbuf_discard(e, 0).
 *   ✅ 통과 조건: 소스에 임계값 비교와 조기 return(또는 discard)이 있다
 */
