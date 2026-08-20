#!/usr/bin/env bash
# 09번 채점 (점수제): Red 공격을 Blue 탐지기가 잡는지 여러 케이스로 검사.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %s  %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %s  %s\n' "$3" "${4:-}"; fi
}

echo "╔═══ 09. 변조 vs 탐지 채점 ═══╗"

go generate ./examples/09-tamper-detect/ >/dev/null 2>&1
if go build -o bin/09-tamper-detect ./examples/09-tamper-detect 2>/tmp/09b.txt; then card 20 1 "빌드"
else card 20 0 "빌드" "$(head -1 /tmp/09b.txt)"; echo 중단; exit 1; fi
go build -o bin/08-tc-mangle ./examples/08-tc-mangle >/dev/null 2>&1

# 시나리오 실행: $1=공격종류(none/ttl)  -> 잡은 공격 수 echo
scen() {
  pkill -f bin/09-tamper-detect 2>/dev/null; pkill -f bin/08-tc-mangle 2>/dev/null; sleep 0.5
  ( timeout 9 ./bin/09-tamper-detect -iface lo -ttl > /tmp/09blue.txt 2>&1 & )
  sleep 2
  [ "$1" = ttl ] && ( timeout 6 ./bin/08-tc-mangle -iface lo -action ttl -ttl 42 > /dev/null 2>&1 & ) && sleep 1.5
  ping -c5 -W1 127.0.0.1 >/dev/null 2>&1
  sleep 2
  pkill -f bin/09-tamper-detect 2>/dev/null; pkill -f bin/08-tc-mangle 2>/dev/null; sleep 1
  grep -aoE '잡은 공격: [0-9]+' /tmp/09blue.txt | grep -oE '[0-9]+' | sort -n | tail -1
}

# [1] 평상시 오탐 없음
c0=$(scen none); c0=${c0:-0}
[ "$c0" -eq 0 ] && card 30 1 "평상시 오탐 없음" "경보 $c0" || card 30 0 "평상시 오탐 발생" "경보 $c0"

# [2] TTL 변조 탐지 (핵심)
c1=$(scen ttl); c1=${c1:-0}
[ "$c1" -gt 0 ] && card 50 1 "TTL 변조 탐지" "경보 $c1 🚨" || card 50 0 "TTL 변조 미탐지" "detect.bpf.c TODO(Lv1) 확인"

echo "──────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then printf '  \033[32m🎉 클리어! Blue 가 Red 를 잡는다.\033[0m\n'; exit 0
else printf '  \033[33m아직이다. detect.bpf.c 의 TODO 를 채워라. (막히면 solution/)\033[0m\n'; exit 1; fi
