//go:build ignore

/*
 * 07. 실무형 런타임 감시 에이전트 (Tetragon / Falco 축소판)
 *
 * 01~06 은 "기능 하나"를 배우는 예제였고, 이 예제는 실제 제품에서 쓰는 구조를
 * 최소한으로 재현한다. 실무에서 반드시 필요해지는 것들:
 *
 *   1) 여러 프로브를 하나의 BPF 오브젝트에 담고 이벤트 종류(kind)로 구분한다
 *      -> 맵/링버퍼를 프로브마다 따로 만들면 메모리와 관리 비용이 폭발한다
 *   2) 커널에서 미리 필터링한다 (self PID, cgroup)
 *      -> 유저 공간까지 올려서 버리면 그게 곧 오버헤드다. 자기 자신을 안 걸러내면
 *         에이전트가 자기 로그를 보고 또 이벤트를 만드는 피드백 루프가 생긴다
 *   3) 런타임 설정 맵 (config)
 *      -> 재컴파일 없이 켜고 끈다. 실제 제품은 여기에 정책이 들어간다
 *   4) 유실 카운터 (dropped)
 *      -> 링버퍼가 꽉 차면 이벤트가 사라진다. "몇 개 잃었는지 모르는 관측
 *         시스템"은 신뢰할 수 없다. 반드시 세어서 노출한다
 *   5) cgroup id 를 이벤트에 실어 보낸다
 *      -> 컨테이너/파드 단위로 귀속시키는 유일한 신뢰 가능한 키.
 *         cgroup v2 에서 cgroup id == cgroup 디렉터리의 inode 번호다
 *
 * ┌─ 진행 방법 ──────────────────────────────────────────────────────┐
 * │  make 07          지금 상태로 실행 (아무 이벤트도 안 나온다)      │
 * │  Lv1 → Lv2 → Lv3 순서로 TODO 를 채운다                            │
 * │  make 07-check    단계별 자동 채점                                │
 * │  막히면           solution/audit.bpf.c                            │
 * │                                                                   │
 * │  01~06 은 훅 하나씩이었다. 07 은 그걸 "제품"으로 조립하는 단계다.  │
 * └──────────────────────────────────────────────────────────────────┘
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define PATH_LEN 128
#define AF_INET 2

/* 이벤트 종류 */
#define KIND_EXEC 1
#define KIND_CONNECT 2
#define KIND_UNLINK 3

/* stats 슬롯 */
#define STAT_EXEC 0
#define STAT_CONNECT 1
#define STAT_UNLINK 2
#define STAT_DROPPED 3  /* 링버퍼 예약 실패 = 유실 */
#define STAT_FILTERED 4 /* 커널에서 걸러낸 수 */
#define STAT_MAX 5

struct event {
	__u64 ts;       /* bpf_ktime_get_ns (부팅 기준 단조 시각) */
	__u64 cgroup_id;
	__u32 tgid;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 daddr; /* CONNECT 전용, 네트워크 오더 */
	__u16 dport; /* CONNECT 전용, 호스트 오더 */
	__u8 kind;
	__u8 pad;
	__u8 comm[TASK_COMM_LEN];
	__u8 path[PATH_LEN]; /* EXEC: 실행 파일, UNLINK: 삭제 대상 */
};

struct event *unused_event __attribute__((unused));

/* 유저 공간이 로드 직후 채워 넣는 런타임 설정 */
struct config {
	__u64 cgroup_id; /* 0 이면 전체 추적, 아니면 이 cgroup 만 */
	__u32 self_pid;  /* 에이전트 자신 (피드백 루프 차단) */
	__u8 want_exec;
	__u8 want_connect;
	__u8 want_unlink;
	__u8 pad;
};

struct config *unused_config __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1MB */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct config);
	__uint(max_entries, 1);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

static __always_inline void bump(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v)
		(*v)++;
}

/* 커널 단계 필터. 통과하면 1 을 리턴하고 cgroup id 를 넘겨준다. */
static __always_inline int allowed(__u8 kind, __u64 *cgid_out)
{
	__u32 z = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &z);
	if (!cfg)
		return 0;

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv1 [30점] — 커널 단계 필터를 완성하라
	 *
	 *   실무 에이전트에서 가장 먼저 하는 일이 "안 볼 것을 커널에서 버리기"다.
	 *   유저 공간까지 올려서 버리면 그게 곧 오버헤드고, 자기 자신을 안 걸러내면
	 *   에이전트가 자기 로그를 보고 또 이벤트를 만드는 피드백 루프가 생긴다.
	 *
	 *   할 일 (1) 런타임 설정 반영 — 꺼진 종류는 버린다:
	 *       if (kind == KIND_EXEC && !cfg->want_exec)       return 0;
	 *       if (kind == KIND_CONNECT && !cfg->want_connect) return 0;
	 *       if (kind == KIND_UNLINK && !cfg->want_unlink)   return 0;
	 *
	 *   할 일 (2) 자기 자신 차단 (피드백 루프 방지):
	 *       __u32 tgid = bpf_get_current_pid_tgid() >> 32;
	 *       if (tgid == cfg->self_pid) { bump(STAT_FILTERED); return 0; }
	 *
	 *   할 일 (3) cgroup 범위 제한 + 통과:
	 *       __u64 cgid = bpf_get_current_cgroup_id();
	 *       if (cfg->cgroup_id != 0 && cgid != cfg->cgroup_id) {
	 *               bump(STAT_FILTERED); return 0;
	 *       }
	 *       *cgid_out = cgid;
	 *       return 1;
	 *
	 *   ✅ 통과 조건: EXEC 이벤트가 화면에 찍힌다
	 *   💡 cgroup id 는 컨테이너/파드에 귀속시키는 유일하게 믿을 만한 키다.
	 *      PID 는 네임스페이스마다 다르고 재사용된다.
	 * ══════════════════════════════════════════════════════════════════ */
	/* TODO(Lv1) */

	*cgid_out = 0;
	return 0; /* TODO(Lv1): 필터를 통과하면 1 을 돌려줘야 이벤트가 나간다 */
}

static __always_inline void fill_common(struct event *e, __u8 kind, __u64 cgid)
{
	__u64 id = bpf_get_current_pid_tgid();

	e->ts = bpf_ktime_get_ns();
	e->cgroup_id = cgid;
	e->tgid = id >> 32;
	e->pid = (__u32)id;
	e->uid = 0; /* TODO(Lv2) */
	e->kind = kind;
	e->pad = 0;
	e->daddr = 0;
	e->dport = 0;
	e->path[0] = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv2 [25점] — UID 와 부모 PID 를 채워라
	 *
	 *   UID 는 헬퍼가 있다:
	 *       e->uid = (__u32)bpf_get_current_uid_gid();
	 *
	 *   부모 PID 는 헬퍼가 없다. task_struct 를 CO-RE 로 타고 들어가야 한다:
	 *       struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	 *       e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	 *
	 *   ✅ 통과 조건: PPID 칸이 0 이 아닌 실제 부모 PID 로 찍힌다
	 *   💡 real_parent vs parent: ptrace 중이면 parent 가 디버거로 바뀐다.
	 *      프로세스 계보를 추적할 때는 real_parent 가 맞다.
	 *   💡 BPF_CORE_READ 는 -> 를 연쇄로 따라가며 각 단계에 재배치를 건다.
	 *      task->real_parent->tgid 로 직접 쓰면 오프셋이 박혀 버린다.
	 * ══════════════════════════════════════════════════════════════════ */
	e->ppid = 0; /* TODO(Lv2) */
}

/* ---------------------------------------------------------------- EXEC
 * sys_enter_execve 시점에는 아직 새 이미지가 로드되지 않았으므로
 * comm 은 "실행을 요청한 쪽(보통 셸)" 이름이다. path 가 새로 실행될 파일.
 * 이 차이를 모르고 대시보드를 만들면 계속 헷갈린다.
 */
/* ══════════════════════════════════════════════════════════════════════════
 * 🎯 Lv0 [10점] — 세 프로브의 훅을 직접 찾아라
 *
 *   01~06 에서 배운 훅이 한 파일에 다 모여 있다. 각각 찾아 채운다.
 *
 *   ① EXEC — 프로그램 실행을 잡는다
 *      ls /sys/kernel/debug/tracing/events/syscalls/ | grep execve
 *      형식: SEC("tracepoint/<그룹>/<이벤트>")
 *
 *   ② CONNECT — TCP 연결 시도를 잡는다 (03번과 같은 함수)
 *      bpftrace -l 'kfunc:*tcp_connect*'
 *      형식: SEC("fentry/<함수>")
 *
 *   ③ UNLINK — 파일 삭제를 잡는다 (01번과 같은 함수)
 *      grep ' [tT] do_unlinkat$' /proc/kallsyms
 *      형식: SEC("kprobe/<함수>")
 *
 *   ✅ 통과 조건: "프로브 3 개 부착 완료" 가 출력된다
 *   💡 셋 중 하나만 틀려도 로드가 실패한다. 에러 메시지에 어느 프로그램인지 나온다.
 * ══════════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/TODO")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!allowed(KIND_EXEC, &cgid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		/* TODO(Lv4 보너스): bump(STAT_DROPPED); */
		return 0;
	}

	fill_common(e, KIND_EXEC, cgid);

	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv3 [20점] (1/2) — 실행 파일 경로를 읽어라
	 *
	 *   execve 의 args[0] 은 아직 유저 공간 포인터다. 커널용 헬퍼를 쓰면
	 *   에러도 안 나고 조용히 빈 문자열이 나온다 — 제일 찾기 어려운 버그다.
	 *
	 *   할 일:
	 *       const char *filename = (const char *)ctx->args[0];
	 *       bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
	 * ══════════════════════════════════════════════════════════════════ */
	/* TODO(Lv3) */

	bump(STAT_EXEC);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------------------------------------------------------------- CONNECT */
SEC("fentry/TODO") /* TODO(Lv0) */
int BPF_PROG(trace_tcp_connect, struct sock *sk)
{
	__u64 cgid = 0;
	if (!allowed(KIND_CONNECT, &cgid))
		return 0;

	if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		/* TODO(Lv4 보너스): bump(STAT_DROPPED); */
		return 0;
	}

	fill_common(e, KIND_CONNECT, cgid);
	e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	bump(STAT_CONNECT);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------------------------------------------------------------- UNLINK */
SEC("kprobe/TODO") /* TODO(Lv0) */
int BPF_KPROBE(trace_unlinkat, int dfd, struct filename *name)
{
	__u64 cgid = 0;
	if (!allowed(KIND_UNLINK, &cgid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		/* TODO(Lv4 보너스): bump(STAT_DROPPED); */
		return 0;
	}

	fill_common(e, KIND_UNLINK, cgid);
	/* ══════════════════════════════════════════════════════════════════
	 * 🎯 Lv3 [20점] (2/2) — 삭제 경로를 읽어라
	 *
	 *   여기는 do_unlinkat 이라 경로가 이미 커널로 복사된 뒤다.
	 *   같은 "경로 읽기"인데 헬퍼가 다르다는 걸 확인하는 게 이 단계의 목적이다.
	 *
	 *   할 일:
	 *       bpf_probe_read_kernel_str(&e->path, sizeof(e->path),
	 *                                 BPF_CORE_READ(name, name));
	 *
	 *   ✅ 통과 조건: UNLINK 행의 DETAIL 에 삭제한 실제 경로가 찍힌다
	 * ══════════════════════════════════════════════════════════════════ */
	/* TODO(Lv3) */

	bump(STAT_UNLINK);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * 🏆 Lv4 [10점] — 유실을 세어라 (보너스)
 *
 *   링버퍼가 꽉 차면 bpf_ringbuf_reserve() 가 NULL 을 돌려주고 이벤트가 사라진다.
 *   "몇 개 잃었는지 모르는 관측 시스템"은 신뢰할 수 없다.
 *
 *   할 일: 세 프로브 각각에서 reserve 실패 시 bump(STAT_DROPPED); 를 부른다.
 *
 *   ✅ 통과 조건: 소스의 reserve 실패 경로에 bump(STAT_DROPPED) 가 있다
 *   💡 종료 시 main.go 가 "유실=N" 을 빨간색으로 출력한다. 유실이 보이면
 *      링버퍼를 키우거나(1<<20 -> 1<<22) 커널 필터를 더 좁혀야 한다.
 */
