//go:build ignore

/*
 * 02. tracepoint - 시스템콜 트레이싱 + 맵 집계
 *
 * kprobe 와 달리 tracepoint 는 커널이 "여기에 붙어도 된다"고 공식 선언한
 * 지점이다. 이름/인자 레이아웃이 ABI 로 유지되므로 커널 버전이 바뀌어도
 * 잘 깨지지 않는다. 시스템콜은 아키텍처별 심볼 이름(__arm64_sys_openat vs
 * __x64_sys_openat) 문제가 있어서 kprobe 보다 tracepoint 가 훨씬 편하다.
 *
 * 확인:  cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
 *
 * 이벤트를 하나하나 유저 공간으로 보내지 않고 BPF 해시맵에 누적한 뒤
 * 유저 공간이 주기적으로 읽어간다 (= aggregation in kernel). 초당 수만 건이
 * 발생하는 openat 같은 이벤트에서는 이 방식이 압도적으로 저렴하다.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16

struct proc_key {
	__u32 tgid;
	__u8 comm[TASK_COMM_LEN];
};

struct proc_key *unused_proc_key __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct proc_key);
	__type(value, __u64);
	__uint(max_entries, 8192);
} counts SEC(".maps");

/* 전체 호출 수 / 대상 필터에 걸린 수 같은 전역 카운터.
 * PERCPU 배열이라 CPU 간 경쟁이 없다. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} total SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct proc_key key = {};
	__u64 init = 1, *cnt;

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&key.comm, sizeof(key.comm));

	cnt = bpf_map_lookup_elem(&counts, &key);
	if (cnt)
		/* 같은 키에 여러 CPU 가 동시에 접근할 수 있으므로 원자적 증가 */
		__sync_fetch_and_add(cnt, 1);
	else
		bpf_map_update_elem(&counts, &key, &init, BPF_ANY);

	__u32 zero = 0;
	cnt = bpf_map_lookup_elem(&total, &zero);
	if (cnt)
		(*cnt)++; /* PERCPU 이므로 원자 연산 불필요 */

	return 0;
}
