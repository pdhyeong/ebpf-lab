//go:build ignore

/*
 * 10. LSM 보안 게임 (정답본) - 관찰이 아니라 "차단"
 *
 * 지금까지는 전부 관찰/집계였다. LSM(Linux Security Module) 훅은 다르다:
 * 반환값으로 커널의 행동을 막을 수 있다. -EPERM 을 리턴하면 그 작업이
 * 실제로 거부된다. Cilium 의 일부 정책, 그리고 컨테이너 런타임 보안 제품이
 * 이 방식을 쓴다.
 *
 * 이 커널은 CONFIG_LSM 에 bpf 가 들어있어(capability,bpf) 실제 차단이 된다.
 *
 * 게임: "malware" 로 끝나는 실행 파일의 실행을 막는다.
 *       cp /bin/echo /tmp/malware; /tmp/malware  -> Operation not permitted
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define NAME_LEN 64

/* 차단 횟수 (검증용) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2); /* [0]=검사한 exec, [1]=차단한 exec */
} gstats SEC(".maps");

static __always_inline void bump(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&gstats, &i);
	if (v)
		(*v)++;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_guard, struct linux_binprm *bprm, int ret)
{
	/* 다른 LSM 이 이미 거부했으면 그 결정을 존중한다. */
	if (ret)
		return ret;

	bump(0);

	char name[NAME_LEN] = {};
	const char *fn = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(name, sizeof(name), fn);

	int len = 0;
#pragma unroll
	for (int i = 0; i < NAME_LEN - 7; i++) {
		if (name[i] == 0) {
			len = i;
			break;
		}
	}

	/* 경로가 "malware" 로 끝나면 실행 거부 */
	if (len >= 7 &&
	    name[len - 7] == 'm' && name[len - 6] == 'a' &&
	    name[len - 5] == 'l' && name[len - 4] == 'w' &&
	    name[len - 3] == 'a' && name[len - 2] == 'r' &&
	    name[len - 1] == 'e') {
		bump(1);
		return -1; /* -EPERM */
	}
	return 0;
}
