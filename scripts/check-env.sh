#!/usr/bin/env bash
# eBPF 실습에 필요한 커널 기능이 실제로 켜져 있는지 점검한다.
# 컨테이너 안에서 실행할 것:  make check
set -uo pipefail

pass=0
fail=0

ok()   { printf '  \033[32m[ OK ]\033[0m %s\n' "$1"; pass=$((pass+1)); }
no()   { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; fail=$((fail+1)); }
warn() { printf '  \033[33m[WARN]\033[0m %s\n' "$1"; }
hdr()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

if [ ! -f /.dockerenv ]; then
  echo "이 스크립트는 컨테이너 안에서 실행해야 한다. 호스트에서는 'make check' 를 쓰면 자동으로 들어간다."
fi

hdr "1. 실행 환경"
echo "  커널      : $(uname -r) $(uname -m)"
echo "  배포판    : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
command -v clang   >/dev/null && echo "  clang     : $(clang --version | head -1)"
command -v go      >/dev/null && echo "  go        : $(go version)"
command -v bpftool >/dev/null && echo "  bpftool   : $(bpftool version | head -1)"

hdr "2. 권한 / 네임스페이스"
if [ "$(id -u)" = 0 ]; then ok "root 로 실행 중"; else no "root 가 아니다 -- BPF 로드 불가"; fi
caps=$(grep CapEff /proc/self/status | awk '{print $2}')
case "$caps" in
  *ffffffffff) ok "전체 capability 보유 (CapEff=$caps)" ;;
  *) warn "CapEff=$caps -- BPF/PERFMON/SYS_ADMIN 이 없으면 일부 예제가 실패한다" ;;
esac
if [ "$(readlink /proc/self/ns/pid)" != "$(readlink /proc/1/ns/pid)" ]; then
  warn "PID 네임스페이스가 호스트와 다르다"
else
  ok "호스트 PID 네임스페이스 공유 (pid: host)"
fi

hdr "3. BTF (CO-RE / fentry 의 전제 조건)"
if [ -r /sys/kernel/btf/vmlinux ]; then
  ok "/sys/kernel/btf/vmlinux 존재 ($(stat -c %s /sys/kernel/btf/vmlinux) bytes)"
else
  no "/sys/kernel/btf/vmlinux 없음 -- CO-RE 및 fentry 사용 불가"
fi
if [ -s /lab/include/vmlinux.h ]; then
  ok "include/vmlinux.h 생성됨 ($(wc -l < /lab/include/vmlinux.h) 줄)"
else
  warn "include/vmlinux.h 없음 -- 'make vmlinux' 실행 필요"
fi

hdr "4. tracefs (kprobe / tracepoint)"
TRACEFS=""
for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do
  [ -d "$d/events" ] && TRACEFS="$d" && break
done
if [ -n "$TRACEFS" ]; then
  ok "tracefs 마운트: $TRACEFS"
  [ -e "$TRACEFS/kprobe_events" ]  && ok "kprobe_events 사용 가능"  || no "kprobe_events 없음"
  [ -e "$TRACEFS/uprobe_events" ]  && ok "uprobe_events 사용 가능"  || no "uprobe_events 없음"
  n=$(ls "$TRACEFS/events/syscalls" 2>/dev/null | wc -l)
  [ "$n" -gt 0 ] && ok "syscalls tracepoint $n 개 노출" || no "syscalls tracepoint 없음"
else
  no "tracefs 를 못 찾았다 -- compose 의 /sys/kernel/debug 마운트 확인"
fi

TMPDIR_CHK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_CHK"' EXIT

hdr "5. 커널 컴파일 옵션"
if [ -r /proc/config.gz ]; then
  # 큰 출력은 변수에 담아 반복 grep 하지 않고 파일로 떨어뜨린다.
  zcat /proc/config.gz > "$TMPDIR_CHK/config" 2>/dev/null
  want="BPF_SYSCALL BPF_JIT DEBUG_INFO_BTF KPROBES UPROBES BPF_EVENTS PERF_EVENTS DYNAMIC_FTRACE_WITH_DIRECT_CALLS NET_CLS_BPF CGROUP_BPF BPF_LSM"
  for c in $want; do
    if grep -qx "CONFIG_${c}=y" "$TMPDIR_CHK/config"; then
      ok "CONFIG_${c}=y"
    else
      warn "CONFIG_${c} 미설정"
    fi
  done
else
  warn "/proc/config.gz 없음 -- 커널 옵션 확인 생략"
fi

hdr "6. 기능 실제 테스트 (bpftool feature probe)"
if command -v bpftool >/dev/null; then
  bpftool feature probe > "$TMPDIR_CHK/probe" 2>/dev/null
  for t in kprobe tracepoint raw_tracepoint xdp sched_cls tracing lsm; do
    if grep -qx "eBPF program_type $t is available" "$TMPDIR_CHK/probe"; then
      ok "program_type $t 사용 가능"
    else
      warn "program_type $t 사용 불가"
    fi
  done
  for m in hash array percpu_array ringbuf lru_hash lpm_trie sk_storage; do
    if grep -qx "eBPF map_type $m is available" "$TMPDIR_CHK/probe"; then
      ok "map_type $m 사용 가능"
    else
      warn "map_type $m 사용 불가"
    fi
  done
else
  warn "bpftool 없음"
fi

hdr "7. 트레이싱 대상 심볼 존재 확인"
for sym in do_unlinkat tcp_connect tcp_v4_connect vfs_read; do
  if grep -qE " (t|T) ${sym}\$" /proc/kallsyms 2>/dev/null; then
    ok "kallsyms: $sym"
  else
    warn "kallsyms: $sym 없음 (해당 예제는 심볼을 바꿔야 한다)"
  fi
done

hdr "결과"
printf '  통과 %d / 실패 %d\n' "$pass" "$fail"
if [ "$fail" -eq 0 ]; then
  printf '  \033[32m실습 준비 완료.\033[0m\n'
else
  printf '  \033[31m실패 항목을 먼저 해결할 것.\033[0m\n'
fi
exit 0
