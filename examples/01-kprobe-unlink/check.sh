#!/usr/bin/env bash
# 01번 채점 (단계별 점수제): kprobe 가 파일 삭제를 제대로 관측하는지.
#   Lv1 링버퍼 예약 -> Lv2 프로세스 식별 -> Lv3 파일명 -> Lv4 커널 필터(보너스)
# 앞 단계가 막히면 뒤 단계는 건너뛴다. 순서대로 뚫는 게 목적이다.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %-28s %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %-28s %s\n' "$3" "${4:-}"; fi
}
skip() { total=$((total+$1)); printf '  \033[90m⏭  [  0점] %-28s %s\033[0m\n' "$2" "${3:-}"; }

echo "╔═══ 01. kprobe 파일 삭제 추적 채점 ═══╗"

# ---------------------------------------------------------------- Lv0 빌드
go generate ./examples/01-kprobe-unlink/ >/dev/null 2>&1
if go build -o bin/01-kprobe-unlink ./examples/01-kprobe-unlink 2>/tmp/01b.txt; then
  card 15 1 "Lv0 빌드"
else
  card 15 0 "Lv0 빌드 실패" "$(head -3 /tmp/01b.txt | tr '\n' ' ')"
  echo "  → 컴파일부터 통과해야 한다. verifier 에러면 마지막 몇 줄을 읽어라."
  exit 1
fi

# ---------------------------------------------------------------- 시나리오
TAG="ebpflab01-$$"
RMFILE="/tmp/${TAG}-byrm"
FINDFILE="/tmp/${TAG}-byfind"

pkill -f bin/01-kprobe-unlink 2>/dev/null; sleep 0.5
: > "$RMFILE"; : > "$FINDFILE"
( timeout 10 ./bin/01-kprobe-unlink > /tmp/01.txt 2>&1 & )
sleep 2.5
rm -f "$RMFILE"
find /tmp -maxdepth 1 -name "${TAG}-byfind" -delete 2>/dev/null
sleep 2
pkill -f bin/01-kprobe-unlink 2>/dev/null; sleep 1

# 헤더를 제외한 데이터 줄 (PID 로 시작하는 줄)
DATA=$(grep -aE '^[0-9]+[[:space:]]' /tmp/01.txt || true)
NLINES=$(printf '%s' "$DATA" | grep -c . || true)

# ---------------------------------------------------------------- Lv1 이벤트
if [ "${NLINES:-0}" -gt 0 ]; then
  card 25 1 "Lv1 링버퍼로 이벤트 전달" "이벤트 ${NLINES}건"
  LV1=1
else
  card 25 0 "Lv1 이벤트가 안 온다" "unlink.bpf.c 의 Lv1 TODO"
  echo "  → bpf_ringbuf_reserve() 가 빠졌다. e = NULL; 을 교체하라."
  LV1=0
fi

# ---------------------------------------------------------------- Lv2 프로세스 식별
if [ "$LV1" = 1 ]; then
  if printf '%s\n' "$DATA" | awk '{print $3}' | grep -qx 'rm'; then
    card 25 1 "Lv2 프로세스 식별(comm/pid)" "COMM=rm 확인"
    LV2=1
  else
    card 25 0 "Lv2 COMM 이 비어 있다" "unlink.bpf.c 의 Lv2 TODO"
    echo "  → bpf_get_current_comm() 과 pid_tgid 분해가 빠졌다."
    LV2=0
  fi
else
  skip 25 "Lv2 (Lv1 먼저)"; LV2=0
fi

# ---------------------------------------------------------------- Lv3 파일명
if [ "$LV2" = 1 ]; then
  if grep -aq "${TAG}-byrm" /tmp/01.txt; then
    card 25 1 "Lv3 삭제 경로 읽기" "${TAG}-byrm 확인"
    LV3=1
  else
    card 25 0 "Lv3 파일명이 안 나온다" "unlink.bpf.c 의 Lv3 TODO"
    echo "  → BPF_CORE_READ(name, name) + bpf_probe_read_kernel_str() 이 빠졌다."
    LV3=0
  fi
else
  skip 25 "Lv3 (Lv2 먼저)"; LV3=0
fi

# ---------------------------------------------------------------- Lv4 보너스
if [ "$LV3" = 1 ]; then
  if grep -aq "${TAG}-byrm" /tmp/01.txt && ! grep -aq "${TAG}-byfind" /tmp/01.txt; then
    card 10 1 "Lv4 커널 단계 필터 (보너스)" "rm 만 통과, find 는 차단"
  else
    card 10 0 "Lv4 미구현 (보너스)" "rm/find 를 둘 다 잡고 있다"
    echo "  → 선택 과제다. comm 이 rm 이 아니면 bpf_ringbuf_discard() 로 버려라."
  fi
else
  skip 10 "Lv4 (보너스, Lv3 먼저)"
fi

rm -f "$RMFILE" "$FINDFILE" 2>/dev/null
echo "──────────────────────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then
  printf '  \033[32m🎉 클리어! kprobe 로 "누가 무슨 파일을 지웠나"를 관측했다.\033[0m\n'
  printf '  다음: examples/01-kprobe-unlink/STUDY.html 로 이론 정리 + OX 퀴즈 → make 02\n'
  exit 0
else
  printf '  \033[33m아직이다. unlink.bpf.c 의 TODO 를 순서대로 채워라. (막히면 solution/)\033[0m\n'
  exit 1
fi
