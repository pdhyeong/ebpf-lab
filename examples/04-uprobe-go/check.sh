#!/usr/bin/env bash
# 04번 채점 (단계별 점수제): uprobe 로 Go 함수 진입과 인자를 잡는지.
#   Lv1 이벤트 -> Lv2 프로세스/시각 -> Lv3 함수 인자 -> Lv4 필터(보너스)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %-30s %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %-30s %s\n' "$3" "${4:-}"; fi
}
skip() { total=$((total+$1)); printf '  \033[90m⏭  [  0점] %-30s %s\033[0m\n' "$2" "${3:-}"; }

finish() {
echo "──────────────────────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then
  printf '  \033[32m🎉 클리어! 커널 밖(유저 공간) 함수까지 eBPF 로 잡았다.\033[0m\n'
  printf '  다음: examples/04-uprobe-go/STUDY.html (이론 + OX 퀴즈) → make 05\n'; exit 0
else
  printf '  \033[33m아직이다. uprobe.bpf.c 의 TODO 를 순서대로 채워라. (막히면 solution/)\033[0m\n'; exit 1
fi
}

echo "╔═══ 04. uprobe Go 함수 트레이싱 채점 ═══╗"

WORKLOAD=/opt/lab/bin/workload
mkdir -p /opt/lab/bin
go build -o "$WORKLOAD" ./target/workload >/dev/null 2>&1
# uprobe 는 virtiofs(/lab) 위의 파일에 못 붙는다. 반드시 컨테이너 FS 에서 실행.
pgrep -x workload >/dev/null || { nohup "$WORKLOAD" >/tmp/workload.log 2>&1 & sleep 1; }

go generate ./examples/04-uprobe-go/ >/dev/null 2>&1
if go build -o bin/04-uprobe-go ./examples/04-uprobe-go 2>/tmp/04b.txt; then
  card 5 1 "Lv0-a 빌드"
else
  card 5 0 "Lv0-a 빌드 실패" "$(head -3 /tmp/04b.txt | tr '\n' ' ')"; exit 1
fi

pkill -f bin/04-uprobe-go 2>/dev/null; sleep 0.5
( timeout 10 ./bin/04-uprobe-go -bin "$WORKLOAD" -sym main.compute > /tmp/04.txt 2>&1 & )
sleep 6
pkill -f bin/04-uprobe-go 2>/dev/null; sleep 1

# UPTIME PID TID COMM ARG
ROWS=$(awk 'NF==5 && $2 ~ /^[0-9]+$/ && $5 ~ /^-?[0-9]+$/ {print}' /tmp/04.txt || true)
NROWS=$(printf '%s' "$ROWS" | grep -c . || true)

# ---------------------------------------------------------------- Lv0-b 훅 부착
if grep -aq '부착' /tmp/04.txt; then
  card 10 1 "Lv0-b 훅에 부착 성공"
else
  card 10 0 "Lv0-b 훅 부착 실패" "SEC() 을 직접 찾아 채워라"
  echo "  ↳ $(grep -am1 'unspecified\|실패\|rror' /tmp/04.txt || echo '프로그램이 부착 메시지를 출력하지 못했다')"
  echo "  → SEC 의 앞부분이 프로그램 타입이다. uprobe 는 무엇으로 시작해야 하나?"
  skip 30 "Lv1 (Lv0 먼저)"
  skip 25 "Lv2 (Lv0 먼저)"
  skip 20 "Lv3 (Lv0 먼저)"
  skip 10 "Lv4 (Lv0 먼저)"
  finish
fi

if [ "${NROWS:-0}" -gt 0 ]; then
  card 30 1 "Lv1 uprobe 이벤트 수신" "${NROWS}건"
  LV1=1
else
  card 30 0 "Lv1 이벤트가 안 온다" "$(head -2 /tmp/04.txt | tr '\n' ' ')"
  echo "  → bpf_ringbuf_reserve() 가 빠졌다. (workload 가 안 떠 있으면 make workload)"
  LV1=0
fi

if [ "$LV1" = 1 ]; then
  if printf '%s\n' "$ROWS" | awk '{print $4}' | grep -qx 'workload'; then
    card 25 1 "Lv2 프로세스 식별 + 시각" "COMM=workload"
    LV2=1
  else
    card 25 0 "Lv2 COMM 이 비어 있다" "uprobe.bpf.c 의 Lv2 TODO"; LV2=0
  fi
else
  skip 25 "Lv2 (Lv1 먼저)"; LV2=0
fi

if [ "$LV2" = 1 ]; then
  if printf '%s\n' "$ROWS" | awk '$5+0 != 0 {f=1} END {exit !f}'; then
    ARGV=$(printf '%s\n' "$ROWS" | awk '$5+0!=0 {print $5; exit}')
    card 20 1 "Lv3 함수 인자 읽기" "ARG=${ARGV}"
    LV3=1
  else
    card 20 0 "Lv3 ARG 가 계속 0" "uprobe.bpf.c 의 Lv3 TODO"
    echo "  → e->arg = n; 한 줄이다. BPF_UPROBE 가 이미 레지스터에서 뽑아 놨다."
    LV3=0
  fi
else
  skip 20 "Lv3 (Lv2 먼저)"; LV3=0
fi

if [ "$LV3" = 1 ]; then
  if grep -qE 'bpf_ringbuf_discard|if \(n [<>]' examples/04-uprobe-go/uprobe.bpf.c; then
    card 10 1 "Lv4 인자 기반 필터 (보너스)" "필터 코드 확인"
  else
    card 10 0 "Lv4 미구현 (보너스)" "모든 호출이 올라온다"
  fi
else
  skip 10 "Lv4 (보너스, Lv3 먼저)"
fi


finish
