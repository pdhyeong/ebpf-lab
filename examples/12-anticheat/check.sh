#!/usr/bin/env bash
# 12번 채점 (점수제): 치트(HP>100)를 안티치트가 잡는지 검사.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %s  %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %s  %s\n' "$3" "${4:-}"; fi
}

echo "╔═══ 12. 안티치트 채점 ═══╗"

go build -o /opt/lab/bin/game ./target/game >/dev/null 2>&1
go generate ./examples/12-anticheat/ >/dev/null 2>&1
if go build -o bin/12-anticheat ./examples/12-anticheat 2>/tmp/12b.txt; then card 20 1 "빌드"
else card 20 0 "빌드" "$(head -1 /tmp/12b.txt)"; echo 중단; exit 1; fi

# 시나리오: $1=normal/cheat -> 치트 탐지 수
scen() {
  pkill -f bin/12-anticheat 2>/dev/null; pkill -x game 2>/dev/null; sleep 0.5
  ( timeout 9 ./bin/12-anticheat > /tmp/12ac.txt 2>&1 & )
  sleep 2
  if [ "$1" = cheat ]; then ( timeout 4 /opt/lab/bin/game -cheat >/dev/null 2>&1 & )
  else ( timeout 4 /opt/lab/bin/game >/dev/null 2>&1 & ); fi
  sleep 4.5
  pkill -f bin/12-anticheat 2>/dev/null; pkill -x game 2>/dev/null; sleep 1
  grep -aoE '치트: [0-9]+' /tmp/12ac.txt | grep -oE '[0-9]+' | sort -n | tail -1
}

# [1] 정상 플레이는 조용해야
c0=$(scen normal); c0=${c0:-0}
[ "$c0" -eq 0 ] && card 35 1 "정상 플레이 오탐 없음" "탐지 $c0" || card 35 0 "정상 플레이 오탐" "탐지 $c0"

# [2] 치트는 잡혀야
c1=$(scen cheat); c1=${c1:-0}
[ "$c1" -gt 0 ] && card 45 1 "치트(HP>100) 탐지" "탐지 $c1 🚨" || card 45 0 "치트 미탐지" "anticheat.bpf.c TODO 확인"

pkill -f bin/12-anticheat 2>/dev/null; pkill -x game 2>/dev/null
echo "──────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then printf '  \033[32m🎉 클리어! 치트를 잡는다.\033[0m\n'; exit 0
else printf '  \033[33m아직이다. anticheat.bpf.c 의 TODO 를 채워라. (막히면 solution/)\033[0m\n'; exit 1; fi
