#!/usr/bin/env bash
# 00. 훅 사냥 채점
#   1) 존재 검증 — 적어낸 훅이 이 커널에 실제로 있는가
#   2) 정답 검증 — 목표에 맞는 훅인가 (정답이 여러 개인 문제도 있다)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

ANSWERS="examples/00-hunt/answers.txt"
TRACE=/sys/kernel/debug/tracing/events
WORKLOAD=/opt/lab/bin/workload
score=0; total=0; PASS_MARK=70

green() { printf '\033[32m%s\033[0m' "$1"; }
red()   { printf '\033[31m%s\033[0m' "$1"; }
dim()   { printf '\033[90m%s\033[0m' "$1"; }

echo "╔═══ 00. 훅 사냥 채점 ═══╗"
echo

[ -f "$ANSWERS" ] || { echo "답안지가 없다: $ANSWERS"; exit 1; }
[ -x "$WORKLOAD" ] || go build -o "$WORKLOAD" ./target/workload >/dev/null 2>&1

# 답안 읽기
declare -a ANS
for i in $(seq 1 10); do ANS[$i]=""; done
while IFS= read -r line; do
  line="${line%%#*}"
  [[ "$line" =~ ^[[:space:]]*([0-9]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
  n="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
  v="$(echo "$v" | xargs 2>/dev/null || true)"
  [ "$n" -ge 1 ] && [ "$n" -le 10 ] && ANS[$n]="$v"
done < "$ANSWERS"

# ---------------------------------------------------------------- 존재 검증
# 주의: set -o pipefail 때문에 bpftool/bpftrace 가 0 이 아닌 코드로 끝나면
# 파이프 전체가 실패로 잡힌다. 그래서 출력을 먼저 변수에 담고 검사한다.
FEATURES="$(bpftool feature probe 2>/dev/null || true)"
KFUNCS="$(bpftrace -l 'kfunc:*' 2>/dev/null || true)"
NMOUT="$(go tool nm "$WORKLOAD" 2>/dev/null || true)"

# $1=훅종류 $2=대상 -> 0 이면 이 커널에 실제로 존재
exists() {
  local kind="$1" tgt="${2:-}"
  case "$kind" in
    tracepoint|tp)
      [ -n "$tgt" ] || return 1
      [ -d "$TRACE/${tgt%%/*}/${tgt##*/}" ] ;;
    kprobe|kretprobe)
      [ -n "$tgt" ] || return 1
      grep -qE " [tT] ${tgt}\$" /proc/kallsyms ;;
    fentry|fexit)
      [ -n "$tgt" ] || return 1
      grep -qE "kfunc:[^:]*:${tgt}\$" <<< "$KFUNCS" ;;
    lsm)
      [ -n "$tgt" ] || return 1
      grep -qE " [tT] bpf_lsm_${tgt}\$" /proc/kallsyms ;;
    uprobe|uretprobe)
      [ -n "$tgt" ] || return 1
      grep -q -- "$tgt" <<< "$NMOUT" ;;
    xdp)
      grep -q 'program_type xdp is available' <<< "$FEATURES" ;;
    tc|tcx|sched_cls)
      grep -q 'program_type sched_cls is available' <<< "$FEATURES" ;;
    *) return 2 ;;
  esac
}

# ---------------------------------------------------------------- 정답표
# 각 목표의 허용 답안 (여러 개 가능). 소문자로 정규화해 비교한다.
declare -A OK
OK[1]="tracepoint syscalls/sys_enter_openat|tracepoint syscalls/sys_enter_openat2|tracepoint syscalls/sys_enter_open"
OK[2]="kprobe do_unlinkat|tracepoint syscalls/sys_enter_unlinkat|tracepoint syscalls/sys_enter_unlink|fentry do_unlinkat"
OK[3]="tracepoint syscalls/sys_enter_execve|tracepoint sched/sched_process_exec|tracepoint syscalls/sys_enter_execveat"
OK[4]="fentry tcp_connect|fexit tcp_connect|kprobe tcp_connect"
OK[5]="tracepoint sched/sched_process_exit"
OK[6]="tracepoint sched/sched_process_fork"
OK[7]="uprobe main.compute"
OK[8]="lsm bprm_check_security|lsm bprm_creds_for_exec|lsm bprm_committed_creds"
OK[9]="lsm file_open"
OK[10]="tc|tcx|sched_cls"

declare -A WHY
WHY[1]="시스템콜은 아키텍처마다 심볼이 달라서(__arm64_sys_* vs __x64_sys_*) tracepoint 를 쓴다. ls $TRACE/syscalls/ | grep openat"
WHY[2]="unlink/unlinkat 각각의 tracepoint 도, 공통 구현부 do_unlinkat 의 kprobe 도 정답이다."
WHY[3]="syscalls/sys_enter_execve 또는 sched/sched_process_exec. ls $TRACE/sched/"
WHY[4]="connect(2) 가 아니라 실제로 SYN 을 보내는 커널 함수다. bpftrace -l 'kfunc:*tcp_connect*'"
WHY[5]="sched 그룹에 전용 tracepoint 가 있다. ls $TRACE/sched/ | grep exit"
WHY[6]="5번과 같은 그룹. ls $TRACE/sched/ | grep fork"
WHY[7]="커널이 아니라 파일의 심볼이다. go tool nm $WORKLOAD | grep compute"
WHY[8]="관찰 훅은 반환값이 무시된다. 차단은 LSM. grep ' [tT] bpf_lsm_bprm' /proc/kallsyms"
WHY[9]="8번과 같은 계열, 훅 이름만 다르다. grep ' [tT] bpf_lsm_file' /proc/kallsyms"
WHY[10]="XDP 는 ingress 전용이라 egress 를 못 본다. skb 가 있는 계층 = TC/TCX."

declare -A TITLE
TITLE[1]="파일 열기 관측"; TITLE[2]="파일 삭제 관측"; TITLE[3]="프로그램 실행 관측"
TITLE[4]="TCP 연결 시도 관측"; TITLE[5]="프로세스 종료 관측"; TITLE[6]="프로세스 fork 관측"
TITLE[7]="유저 공간 함수 관측"; TITLE[8]="실행 차단"; TITLE[9]="파일 열기 차단"
TITLE[10]="egress 패킷 관측"

norm() { echo "$1" | tr 'A-Z' 'a-z' | tr -s ' ' | xargs 2>/dev/null || true; }

blank=0
for i in $(seq 1 10); do
  total=$((total+10))
  raw="${ANS[$i]}"
  a="$(norm "$raw")"
  if [ -z "$a" ]; then
    printf ' %2d. ' "$i"; red "⬜ 미작성"; printf '   %s\n' "${TITLE[$i]}"
    blank=$((blank+1)); continue
  fi

  kind="${a%% *}"; tgt=""
  [ "$a" != "$kind" ] && tgt="${a#* }"

  # 1단계: 존재 검증
  exists "$kind" "$tgt"; rc=$?
  if [ "$rc" != 0 ]; then
    if [ "$rc" = 2 ]; then
      printf ' %2d. ' "$i"; red "⬜ 훅종류?"; printf '   %s  %s\n' "${TITLE[$i]}" "$(dim "'$kind' 은 없는 훅 종류다")"
    else
      printf ' %2d. ' "$i"; red "⬜ 없음  "; printf '   %s  %s\n' "${TITLE[$i]}" "$(dim "'$raw' 는 이 커널에 존재하지 않는다")"
      echo "     $(dim "→ 코드를 쓰기 전에 대상이 있는지부터 확인하는 게 이 랩의 목적이다.")"
      echo "     $(dim "  ${WHY[$i]}")"
    fi
    continue
  fi

  # 2단계: 정답 검증
  hit=0
  IFS='|' read -ra CANDS <<< "${OK[$i]}"
  for c in "${CANDS[@]}"; do [ "$a" = "$(norm "$c")" ] && hit=1 && break; done

  if [ "$hit" = 1 ]; then
    score=$((score+10))
    printf ' %2d. ' "$i"; green "✅ 정답  "; printf '   %s  %s\n' "${TITLE[$i]}" "$(dim "$raw")"
  else
    printf ' %2d. ' "$i"; red "⬜ 불일치"; printf '   %s  %s\n' "${TITLE[$i]}" "$(dim "$raw — 존재하지만 목표와 안 맞는다")"
    echo "     $(dim "→ ${WHY[$i]}")"
  fi
done

echo
echo "──────────────────────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
[ "$blank" -gt 0 ] && printf '  %s\n' "$(dim "미작성 ${blank}문제 — examples/00-hunt/answers.txt")"
if [ "$score" -ge "$PASS_MARK" ]; then
  printf '  \033[32m🎉 클리어! 훅을 스스로 찾을 수 있다. 이게 eBPF 개발의 8할이다.\033[0m\n'
  printf '  다음: examples/00-hunt/STUDY.html (선택 기준 정리 + 퀴즈) → make 01\n'
  exit 0
else
  printf '  \033[33m아직이다. examples/00-hunt/TARGETS.md 의 탐색 도구로 직접 찾아라.\033[0m\n'
  exit 1
fi
