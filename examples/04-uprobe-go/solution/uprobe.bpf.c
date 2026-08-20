//go:build ignore

/*
 * 04. uprobe - 유저 공간 함수 트레이싱 (Go 바이너리 대상)
 *
 * uprobe 는 ELF 파일의 오프셋에 트랩을 심는다. 커널이 아니라 우리가 만든
 * Go 프로그램의 함수를 잡는 것이다. 여기서는 target/workload 의
 *   func compute(n int) int
 * 진입점을 잡아 인자 n 을 읽는다.
 *
 * Go 함수 인자 읽기 주의점:
 *   - Go 1.17+ 는 레지스터 기반 호출 규약(regabi)을 쓴다. arm64 에서 첫 정수
 *     인자는 X0, amd64 에서는 RAX 다. libbpf 의 PT_REGS_PARM1 매크로가
 *     아키텍처별로 알아서 맞는 레지스터를 골라준다.
 *   - uretprobe 는 Go 에서 쓰지 말 것. 고루틴 스택이 이동하면 uretprobe 가
 *     심어둔 복귀 주소가 무효화되어 대상 프로세스가 죽을 수 있다.
 *     반환값이 필요하면 "함수의 return 지점 오프셋에 uprobe" 를 붙인다.
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
SEC("uprobe/main.compute")
int BPF_UPROBE(uprobe_compute, long n)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = (__u32)id;
	e->arg = n;
	e->ts = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
