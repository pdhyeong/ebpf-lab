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

	if (kind == KIND_EXEC && !cfg->want_exec)
		return 0;
	if (kind == KIND_CONNECT && !cfg->want_connect)
		return 0;
	if (kind == KIND_UNLINK && !cfg->want_unlink)
		return 0;

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (tgid == cfg->self_pid) {
		bump(STAT_FILTERED);
		return 0;
	}

	__u64 cgid = bpf_get_current_cgroup_id();
	if (cfg->cgroup_id != 0 && cgid != cfg->cgroup_id) {
		bump(STAT_FILTERED);
		return 0;
	}

	*cgid_out = cgid;
	return 1;
}

static __always_inline void fill_common(struct event *e, __u8 kind, __u64 cgid)
{
	__u64 id = bpf_get_current_pid_tgid();

	e->ts = bpf_ktime_get_ns();
	e->cgroup_id = cgid;
	e->tgid = id >> 32;
	e->pid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->kind = kind;
	e->pad = 0;
	e->daddr = 0;
	e->dport = 0;
	e->path[0] = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* 부모 PID 는 헬퍼가 없어서 task_struct 를 CO-RE 로 타고 들어가야 한다. */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
}

/* ---------------------------------------------------------------- EXEC
 * sys_enter_execve 시점에는 아직 새 이미지가 로드되지 않았으므로
 * comm 은 "실행을 요청한 쪽(보통 셸)" 이름이다. path 가 새로 실행될 파일.
 * 이 차이를 모르고 대시보드를 만들면 계속 헷갈린다.
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgid = 0;
	if (!allowed(KIND_EXEC, &cgid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump(STAT_DROPPED);
		return 0;
	}

	fill_common(e, KIND_EXEC, cgid);

	/* args[0] 은 유저 공간 포인터다. 커널 포인터용 헬퍼를 쓰면 실패한다. */
	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);

	bump(STAT_EXEC);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------------------------------------------------------------- CONNECT */
SEC("fentry/tcp_connect")
int BPF_PROG(trace_tcp_connect, struct sock *sk)
{
	__u64 cgid = 0;
	if (!allowed(KIND_CONNECT, &cgid))
		return 0;

	if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump(STAT_DROPPED);
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
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(trace_unlinkat, int dfd, struct filename *name)
{
	__u64 cgid = 0;
	if (!allowed(KIND_UNLINK, &cgid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump(STAT_DROPPED);
		return 0;
	}

	fill_common(e, KIND_UNLINK, cgid);
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), BPF_CORE_READ(name, name));

	bump(STAT_UNLINK);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
