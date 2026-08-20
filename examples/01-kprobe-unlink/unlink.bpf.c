//go:build ignore

/*
 * 01. kprobe - 커널 함수 진입점 트레이싱
 *
 * do_unlinkat() 은 unlink(2)/unlinkat(2) 시스템콜의 실제 구현부다.
 *   fs/namei.c:  int do_unlinkat(int dfd, struct filename *name)
 *
 * kprobe 는 "커널 함수 주소에 브레이크포인트를 심는" 방식이라
 * 어떤 함수에도 붙을 수 있지만, 함수 시그니처가 바뀌면 같이 깨진다.
 * (비교: 03번 예제의 fentry 는 BTF 기반이라 타입 체크를 받는다)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define FNAME_LEN 96

struct event {
	__u32 tgid;               /* 유저 공간에서 말하는 PID */
	__u32 pid;                /* 커널 관점의 tid */
	__u8 comm[TASK_COMM_LEN]; /* 프로세스 이름 */
	__u8 filename[FNAME_LEN]; /* 지우려는 경로 */
};

/* bpf2go 가 struct event 를 Go 구조체로 뽑아내도록 강제하는 관용적 트릭.
 * 실제로 참조되지 않으면 BTF 에 타입이 남지 않는다. */
struct event *unused_event __attribute__((unused));

/* 커널 -> 유저 공간 이벤트 전달용 링버퍼 (perf buffer 의 후속) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	struct event *e;

	/* 링버퍼에서 공간을 먼저 예약한다. 실패하면 버퍼가 꽉 찬 것. */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = (__u32)id;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* struct filename 의 name 필드는 커널 메모리를 가리키는 포인터다.
	 * BPF_CORE_READ 는 CO-RE 재배치를 걸어서, 필드 오프셋이 다른
	 * 커널에서도 동작하게 만들어 준다. */
	const char *fname = BPF_CORE_READ(name, name);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
