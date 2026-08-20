//go:build ignore

/*
 * 02. tracepoint - 안정적인 후킹 + 커널 내 집계      [🎯 실습 랩 — 빈칸을 채운다]
 *
 * kprobe 와 달리 tracepoint 는 커널이 "여기에 붙어도 된다"고 공식 선언한
 * 지점이다. 이름/인자 레이아웃이 ABI 로 유지되므로 커널 버전이 바뀌어도
 * 잘 깨지지 않는다. 시스템콜은 아키텍처별 심볼 이름(__arm64_sys_openat vs
 * __x64_sys_openat) 문제가 있어서 kprobe 보다 tracepoint 가 훨씬 편하다.
 *
 * 확인:  cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
 *
 * 이벤트를 하나하나 유저 공간으로 보내지 않고 BPF 해시맵에 누적한 뒤
 * 유저 공간이 주기적으로 읽어간다 (= aggregation in kernel). 초당 수천 건이
 * 발생하는 openat 같은 이벤트에서는 이 방식이 압도적으로 저렴하다.
 *
 * ┌─ 진행 방법 ──────────────────────────────────────────────────────┐
 * │  make 02          지금 상태로 실행 (집계가 안 된다)               │
 * │  Lv1 → Lv2 → Lv3 순서로 TODO 를 채운다                            │
 * │  make 02-check    단계별 자동 채점                                │
 * │  막히면           solution/openat.bpf.c                           │
 * └──────────────────────────────────────────────────────────────────┘
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
	/* 🏆 Lv4 보너스: 여기에 __u32 uid; 를 추가한다 */
};

struct proc_key *unused_proc_key __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct proc_key);
	__type(value, __u64);
	__uint(max_entries, 8192);
} counts SEC(".maps");

/* 전체 호출 수 같은 전역 카운터.
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

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv1 [30점] — 키를 만들고 새 프로세스를 맵에 등록하라
	 *
	 *   해시맵의 키는 "누구" 를 뜻한다. 여기서는 (프로세스, 이름) 쌍이다.
	 *
	 *   할 일 (1) 키 채우기:
	 *       key.tgid = bpf_get_current_pid_tgid() >> 32;
	 *       bpf_get_current_comm(&key.comm, sizeof(key.comm));
	 *
	 *   할 일 (2) 없으면 새로 넣기 — 아래 else 절의 (void)init; 을 교체:
	 *       bpf_map_update_elem(&counts, &key, &init, BPF_ANY);
	 *
	 *   ✅ 통과 조건: make 02 출력에 프로세스 행이 나타난다
	 *   ⚠️  struct proc_key key = {}; 의 = {} 를 지우지 마라. 해시 키 비교는
	 *      바이트 단위 memcmp 라서, 초기화 안 된 패딩이 있으면 같은 프로세스가
	 *      매번 다른 항목으로 들어간다.
	 * ══════════════════════════════════════════════════════════════════ */
	key.tgid = 0;    /* TODO(Lv1) */
	key.comm[0] = 0; /* TODO(Lv1) */

	cnt = bpf_map_lookup_elem(&counts, &key);
	if (cnt) {
		/* ══════════════════════════════════════════════════════════
		 * 🎯 Lv2 [25점] — 이미 있는 카운터를 원자적으로 1 증가시켜라
		 *
		 *   일반 HASH 맵의 값은 모든 CPU 가 공유하는 메모리 한 덩어리다.
		 *   CPU 0 과 CPU 3 이 동시에 (*cnt)++ 를 하면
		 *   읽기→더하기→쓰기가 겹쳐서 카운트를 잃는다.
		 *
		 *   할 일:
		 *       __sync_fetch_and_add(cnt, 1);
		 *
		 *   ✅ 통과 조건: 카운트가 1 에서 멈추지 않고 계속 올라간다
		 *   💡 이건 BPF 바이트코드의 lock add 명령으로 컴파일된다.
		 * ══════════════════════════════════════════════════════════ */
		/* TODO(Lv2) */
	} else {
		(void)init; /* TODO(Lv1): bpf_map_update_elem 으로 교체 */
	}

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv3 [20점] — 전체 호출 수를 PERCPU 카운터에 누적하라
	 *
	 *   PERCPU 맵은 CPU 마다 별도 복사본이 있다. lookup 이 "지금 이 CPU 의"
	 *   주소를 돌려주므로 경쟁 자체가 없다 → 원자 연산이 필요 없다.
	 *
	 *   할 일:
	 *       __u32 zero = 0;
	 *       cnt = bpf_map_lookup_elem(&total, &zero);
	 *       if (cnt)
	 *               (*cnt)++;
	 *
	 *   ✅ 통과 조건: "누적 openat 호출 N 건" 의 N 이 0 이 아니다
	 *   💡 유저 공간에서 이걸 읽으면 값 하나가 아니라 CPU 개수만큼의
	 *      슬라이스가 온다. main.go 의 readTotal() 이 직접 합산한다.
	 * ══════════════════════════════════════════════════════════════════ */
	/* TODO(Lv3) */

	return 0;
}

/*
 * 🏆 Lv4 [10점] — 키에 UID 추가 (보너스)
 *
 *   같은 이름의 프로세스라도 실행한 사용자가 다르면 다른 항목으로 세고 싶다.
 *
 *   할 일:
 *     1) struct proc_key 에 __u32 uid; 추가
 *     2) key.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
 *     3) make generate — Go 구조체가 자동으로 따라오는지 확인
 *
 *   ✅ 통과 조건: bpftool map list 의 counts 항목이 key 20B → 24B 로 바뀐다
 *   💡 필드를 __u64 로 넣으면 정렬 때문에 패딩이 생긴다. = {} 초기화가
 *      왜 필수인지 여기서 실감할 수 있다.
 */
