//go:build ignore

/*
 * 13. 미니 백신 (정답본) - 시그니처 기반 파일 접근 차단
 *
 * 진짜 백신은 파일을 스캔해 "알려진 악성 시그니처"와 대조한다. 여기서는
 * 그 축소판을 커널에서 한다: 파일을 여는 순간(lsm/file_open) 파일 이름에
 * 격리 표식(quarantine marker)이 있으면 열기 자체를 -EPERM 으로 막는다.
 *
 * 왜 이름으로 하나? 파일 내용을 uprobe 없이 lsm 훅에서 읽는 건 제약이 크다.
 * 실무 백신도 1차로 경로/이름/확장자로 거르고, 2차로 내용 해시를 본다.
 * 이 예제는 1차 필터를 구현한다. (내용 해시는 확장 과제)
 *
 * 시그니처: 파일명에 ".virus" 가 들어가면 격리 대상으로 본다.
 *   echo x > /tmp/test.virus.txt ; cat /tmp/test.virus.txt  -> Permission denied
 *
 * 정상 파일은 아무 영향 없다.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define NAME_LEN 64

/* [0]=검사한 open, [1]=격리(차단)한 open */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
} avstats SEC(".maps");

static __always_inline void bump(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&avstats, &i);
	if (v)
		(*v)++;
}

/* name 안에 ".virus" 부분문자열이 있는지 (아주 단순한 시그니처 매칭) */
static __always_inline int has_virus_sig(const char *name)
{
#pragma unroll
	for (int i = 0; i < NAME_LEN - 6; i++) {
		if (name[i] == 0)
			break;
		if (name[i] == '.' && name[i + 1] == 'v' && name[i + 2] == 'i' &&
		    name[i + 3] == 'r' && name[i + 4] == 'u' && name[i + 5] == 's')
			return 1;
	}
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(av_scan, struct file *file, int ret)
{
	if (ret)
		return ret; /* 다른 LSM 결정 존중 */

	bump(0);

	char name[NAME_LEN] = {};
	/* file->f_path.dentry->d_name.name 에서 파일명을 읽는다 (CO-RE) */
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	const unsigned char *dn = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_kernel_str(name, sizeof(name), dn);

	if (has_virus_sig(name)) {
		bump(1);
		return -1; /* -EPERM: 격리. 파일을 못 연다. */
	}
	return 0;
}
