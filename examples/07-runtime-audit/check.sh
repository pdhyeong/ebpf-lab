#!/usr/bin/env bash
# 07번 채점 (단계별 점수제): 런타임 감시 에이전트가 실제로 동작하는지.
#   Lv1 커널 필터 -> Lv2 프로세스 계보 -> Lv3 경로 읽기 -> Lv4 유실 카운터(보너스)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %-30s %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %-30s %s\n' "$3" "${4:-}"; fi
}
skip() { total=$((total+$1)); printf '  \033[90m⏭  [  0점] %-30s %s\033[0m\n' "$2" "${3:-}"; }

echo "╔═══ 07. 런타임 감시 에이전트 채점 ═══╗"

go generate ./examples/07-runtime-audit/ >/dev/null 2>&1
if go build -o bin/07-runtime-audit ./examples/07-runtime-audit 2>/tmp/07b.txt; then
  card 15 1 "Lv0 빌드"
else
  card 15 0 "Lv0 빌드 실패" "$(head -3 /tmp/07b.txt | tr '\n' ' ')"; exit 1
fi

TAG="/tmp/ebpflab07-$$"
: > "$TAG"
pkill -f bin/07-runtime-audit 2>/dev/null; sleep 0.5
( timeout 12 ./bin/07-runtime-audit > /tmp/07.txt 2>&1 & )
sleep 3.5
# EXEC 이벤트 발생
for i in 1 2 3; do /bin/true; /bin/echo -n "" ; done
# UNLINK 이벤트 발생
rm -f "$TAG"
sleep 3
pkill -f bin/07-runtime-audit 2>/dev/null; sleep 1.5

# TIME KIND CONTAINER PID PPID UID COMM DETAIL
EXECROWS=$(awk '$2=="EXEC" {print}' /tmp/07.txt || true)
UNLROWS=$(awk '$2=="UNLINK" {print}' /tmp/07.txt || true)
NEXEC=$(printf '%s' "$EXECROWS" | grep -c . || true)

if [ "${NEXEC:-0}" -gt 0 ]; then
  card 30 1 "Lv1 커널 필터 통과 + 이벤트" "EXEC ${NEXEC}건"
  LV1=1
else
  card 30 0 "Lv1 이벤트가 하나도 없다" "audit.bpf.c 의 Lv1 TODO"
  echo "  → allowed() 가 항상 0 을 돌려준다. 필터 3단계를 채우고 마지막에 return 1."
  LV1=0
fi

if [ "$LV1" = 1 ]; then
  if printf '%s\n' "$EXECROWS" | awk '$5+0 != 0 {f=1} END {exit !f}'; then
    PP=$(printf '%s\n' "$EXECROWS" | awk '$5+0!=0 {print $5; exit}')
    card 25 1 "Lv2 UID/부모 PID (CO-RE)" "PPID=${PP}"
    LV2=1
  else
    card 25 0 "Lv2 PPID 가 계속 0" "audit.bpf.c 의 Lv2 TODO"
    echo "  → BPF_CORE_READ(task, real_parent, tgid) 가 빠졌다."
    LV2=0
  fi
else
  skip 25 "Lv2 (Lv1 먼저)"; LV2=0
fi

if [ "$LV2" = 1 ]; then
  if grep -aq "$(basename "$TAG")" /tmp/07.txt; then
    card 20 1 "Lv3 경로 읽기 (user/kernel)" "$(basename "$TAG") 확인"
    LV3=1
  else
    card 20 0 "Lv3 경로가 비어 있다" "audit.bpf.c 의 Lv3 TODO"
    echo "  → execve 는 _user, unlink 는 _kernel. 헬퍼를 바꿔 쓰면 조용히 빈 문자열이다."
    LV3=0
  fi
else
  skip 20 "Lv3 (Lv2 먼저)"; LV3=0
fi

if [ "$LV3" = 1 ]; then
  if grep -qE '^[^*/]*bump\(STAT_DROPPED\)' examples/07-runtime-audit/audit.bpf.c; then
    card 10 1 "Lv4 유실 카운터 (보너스)" "STAT_DROPPED 확인"
  else
    card 10 0 "Lv4 미구현 (보너스)" "유실을 세지 않는다"
    echo "  → reserve 실패 경로에 bump(STAT_DROPPED); 를 넣어라."
  fi
else
  skip 10 "Lv4 (보너스, Lv3 먼저)"
fi

rm -f "$TAG" 2>/dev/null
echo "──────────────────────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then
  printf '  \033[32m🎉 클리어! 학습 트랙 완주. Tetragon/Falco 의 축소판을 직접 만들었다.\033[0m\n'
  printf '  다음: examples/07-runtime-audit/STUDY.html (이론 + OX 퀴즈) → 게임 트랙 make 08\n'; exit 0
else
  printf '  \033[33m아직이다. audit.bpf.c 의 TODO 를 순서대로 채워라. (막히면 solution/)\033[0m\n'; exit 1
fi
