//go:build ignore

/*
 * 01. kprobe - 커널 함수 진입점 트레이싱          [🎯 실습 랩 — 빈칸을 채운다]
 *
 * do_unlinkat() 은 unlink(2)/unlinkat(2) 시스템콜의 실제 구현부다.
 *   fs/namei.c:  int do_unlinkat(int dfd, struct filename *name)
 *
 * kprobe 는 "커널 함수 주소에 브레이크포인트를 심는" 방식이라 어떤 함수에도
 * 붙을 수 있지만, 함수 시그니처가 바뀌면 같이 깨진다.
 * (비교: 03번의 fentry 는 BTF 기반이라 타입 체크를 받는다)
 *
 * ┌─ 진행 방법 ──────────────────────────────────────────────────────┐
 * │  make 01          지금 상태로 실행 (아무 이벤트도 안 나온다)      │
 * │  아래 Lv1 → Lv2 → Lv3 순서로 TODO 를 채운다                       │
 * │  make 01-check    단계별 자동 채점                                │
 * │  막히면           solution/unlink.bpf.c                           │
 * └──────────────────────────────────────────────────────────────────┘
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

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv1 [25점] — 링버퍼에서 공간을 예약하라
	 *
	 *   BPF 프로그램은 malloc 이 없다. 이벤트를 보내려면 링버퍼에서
	 *   "이만큼 쓸게" 하고 먼저 자리를 잡아야 한다. 꽉 찼으면 NULL 이 온다.
	 *
	 *   할 일:  아래 e = NULL; 을 이렇게 바꾼다
	 *       e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	 *
	 *   ✅ 통과 조건: rm 을 실행하면 make 01 에 이벤트 줄이 찍힌다
	 *   💡 if (!e) return 0; 은 verifier 가 요구하는 필수 NULL 체크다. 지우면 로드 거부.
	 * ══════════════════════════════════════════════════════════════════ */
	e = NULL; /* TODO(Lv1) */

	if (!e)
		return 0;

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv2 [25점] — 누가 지웠는지 채워라
	 *
	 *   bpf_get_current_pid_tgid() 는 __u64 하나에 두 값을 담아 준다.
	 *       상위 32비트 = TGID = 유저가 말하는 "PID" (프로세스)
	 *       하위 32비트 = PID  = 커널이 말하는 PID = 스레드 ID
	 *
	 *   할 일:
	 *       __u64 id = bpf_get_current_pid_tgid();
	 *       e->tgid = id >> 32;
	 *       e->pid  = (__u32)id;
	 *       bpf_get_current_comm(&e->comm, sizeof(e->comm));
	 *
	 *   ✅ 통과 조건: COMM 칸에 rm 이 찍힌다 (0 이나 빈칸이 아니라)
	 * ══════════════════════════════════════════════════════════════════ */
	e->tgid = 0;    /* TODO(Lv2) */
	e->pid = 0;     /* TODO(Lv2) */
	e->comm[0] = 0; /* TODO(Lv2) */

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv3 [25점] — 어떤 파일인지 읽어라
	 *
	 *   struct filename 의 name 필드는 커널 메모리를 가리키는 포인터다.
	 *   두 단계가 필요하다:
	 *     1) 구조체 필드 읽기 — BPF_CORE_READ 로 CO-RE 재배치를 건다.
	 *        커널마다 필드 오프셋이 달라도 로드 시점에 로더가 고쳐 준다.
	 *     2) 그 포인터가 가리키는 문자열 복사 — 직접 역참조는 verifier 가 막는다.
	 *
	 *   할 일:
	 *       const char *fname = BPF_CORE_READ(name, name);
	 *       bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fname);
	 *
	 *   ✅ 통과 조건: 삭제한 파일의 실제 경로가 FILENAME 칸에 찍힌다
	 *   💡 왜 _kernel 인가? do_unlinkat 시점엔 경로가 이미 커널로 복사된 뒤다.
	 *      시스템콜 진입 직후라면 _user 를 써야 한다 (02번 Lv4 참고).
	 * ══════════════════════════════════════════════════════════════════ */
	e->filename[0] = 0; /* TODO(Lv3) */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * 🏆 Lv4 [10점] — 노이즈 필터 (확장 과제)
 *
 *   지금은 시스템 전체의 삭제가 다 잡힌다. 특정 디렉터리나 특정 프로세스만
 *   보고 싶다면 커널 안에서 걸러야 한다 (유저 공간까지 올려서 버리면 그게 오버헤드).
 *
 *   힌트: comm 을 읽어 앞 두 글자가 "rm" 이 아니면 bpf_ringbuf_discard(e, 0)
 *         후 return 0. submit 대신 discard 를 쓰는 게 핵심이다.
 */
