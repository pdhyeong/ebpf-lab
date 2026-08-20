//go:build ignore

/*
 * 12. 안티치트 게임 (게임판 - TODO 를 채워라) - uprobe 로 메모리 조작 치트 탐지
 *
 * 게임 클라이언트는 신뢰할 수 없다. 치트 프로그램은 게임 메모리를 직접
 * 조작해 체력/재화/좌표를 비정상 값으로 만든다. 서버가 모든 걸 검증하는 게
 * 정석이지만, 클라이언트 함수 호출 자체를 커널에서 감시할 수도 있다.
 *
 * 이 예제는 게임의 setHealth(hp) 함수에 uprobe 를 붙여, 인자 hp 가 게임
 * 규칙(<=MAX_HP)을 위반하면 "치트 의심" 경보를 올린다. 치트 프로그램의
 * 소스를 고치지 않고도, 바이너리에 손대지 않고도 탐지한다.
 *
 * 04번 uprobe 와 같은 원리. 다른 점은 "값을 규칙과 비교해 판정"한다는 것.
 *   - 정상 setHealth(90~100) -> 통과
 *   - 치트 setHealth(9999)   -> 경보
 *
 * (실무 확장: 좌표 텔레포트, 발사 속도(rate) 위반, 재화 급증 등도 같은 방식)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_HP 100 /* 게임 규칙: 체력은 100 을 넘을 수 없다 */
#define TASK_COMM_LEN 16

struct cheat_evt {
	__u32 pid;
	__s64 value;   /* 규칙을 위반한 값 */
	__s64 limit;   /* 위반한 한계 */
	__u8 comm[TASK_COMM_LEN];
};

struct cheat_evt *unused_evt __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} cheats SEC(".maps");

/* [0]=검사한 호출, [1]=치트 판정 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
} acstats SEC(".maps");

static __always_inline void bump(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&acstats, &i);
	if (v)
		(*v)++;
}

SEC("uprobe/setHealth")
int BPF_UPROBE(check_health, long hp)
{
	bump(0); /* 검사한 setHealth 호출 (이건 이미 세어 준다) */

	/* ==================================================================
	 * TODO - 게임 규칙 위반(치트)을 잡아라.
	 *
	 *   정상 플레이는 hp <= MAX_HP(100) 다. 치트는 9999 를 넣는다.
	 *
	 *   할 일: hp > MAX_HP 이면
	 *     1) bump(1);                                   // 치트 카운트
	 *     2) struct cheat_evt *e = bpf_ringbuf_reserve(&cheats, sizeof(*e), 0);
	 *        if (!e) return 0;
	 *     3) e->pid = bpf_get_current_pid_tgid() >> 32;
	 *        e->value = hp;  e->limit = MAX_HP;
	 *        bpf_get_current_comm(&e->comm, sizeof(e->comm));
	 *     4) bpf_ringbuf_submit(e, 0);
	 *
	 *   막히면 solution/anticheat.bpf.c 참고.
	 *
	 *   💡 확장 아이디어(직접): 좌표 텔레포트(직전 좌표와의 거리), 발사 rate
	 *      (직전 호출 시각과의 간격), 재화 급증 등을 같은 방식으로 판정.
	 * ================================================================== */

	return 0;
}
