#!/usr/bin/env bash
# 13번 채점 (점수제): 감염 파일(.virus) 격리, 정상 파일 통과를 검사.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %s  %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %s  %s\n' "$3" "${4:-}"; fi
}

echo "╔═══ 13. 미니 백신 채점 ═══╗"

go generate ./examples/13-mini-av/ >/dev/null 2>&1
if go build -o bin/13-mini-av ./examples/13-mini-av 2>/tmp/13b.txt; then card 20 1 "빌드"
else card 20 0 "빌드" "$(head -1 /tmp/13b.txt)"; echo 중단; exit 1; fi

echo bad > /tmp/sample.virus.txt
echo good > /tmp/normal.txt
pkill -f bin/13-mini-av 2>/dev/null; sleep 0.5
( timeout 10 ./bin/13-mini-av > /tmp/13av.txt 2>&1 & )
sleep 3

# [1] 정상 파일은 읽혀야
if cat /tmp/normal.txt >/dev/null 2>&1; then card 35 1 "정상 파일 접근 허용"
else card 35 0 "정상 파일이 막힘(과잉 격리)"; fi

# [2] 감염 파일은 격리돼야
if cat /tmp/sample.virus.txt >/dev/null 2>&1; then card 45 0 "감염 파일이 열림" "av.bpf.c TODO 확인"
else card 45 1 "감염 파일 격리됨" "🦠"; fi

rm -f /tmp/sample.virus.txt /tmp/normal.txt
pkill -f bin/13-mini-av 2>/dev/null
echo "──────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then printf '  \033[32m🎉 클리어! 감염 파일을 격리한다.\033[0m\n'; exit 0
else printf '  \033[33m아직이다. av.bpf.c 의 TODO 를 채워라. (막히면 solution/)\033[0m\n'; exit 1; fi
