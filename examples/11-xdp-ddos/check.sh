#!/usr/bin/env bash
# 11번 채점 (점수제): SYN flood 를 XDP 필터가 차단하는지 여러 케이스로 검사.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() { # $1=배점 $2=획득(0/1) $3=설명 $4=비고
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %s  %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %s  %s\n' "$3" "${4:-}"; fi
}

echo "╔═══ 11. XDP DDoS 방어 채점 ═══╗"

# [1] 빌드
go generate ./examples/11-xdp-ddos/ >/dev/null 2>&1
if go build -o bin/11-xdp-ddos ./examples/11-xdp-ddos 2>/tmp/11build.txt; then
  card 20 1 "빌드"
else
  card 20 0 "빌드" "$(head -1 /tmp/11build.txt)"
  echo "빌드 실패로 중단"; exit 1
fi

flood() { local n="$1" i; for ((i=0;i<n;i++)); do timeout 0.05 bash -c 'exec 3<>/dev/tcp/127.0.0.1/59999' 2>/dev/null; done; }

pkill -f bin/11-xdp-ddos 2>/dev/null; sleep 0.5
( timeout 14 ./bin/11-xdp-ddos -iface lo -rate 20 > /tmp/11xdp.txt 2>&1 & )
sleep 2

# [2] 정상 트래픽은 통과해야 한다 (소량 SYN)
flood 5
sleep 1
d1=$(grep -aoE '차단: [0-9]+' /tmp/11xdp.txt | grep -oE '[0-9]+' | sort -n | tail -1); d1=${d1:-0}
[ "$d1" -eq 0 ] && card 25 1 "정상 트래픽(소량 SYN)은 통과" "차단 $d1" || card 25 0 "정상 트래픽 오차단" "차단 $d1(과잉)"

# [3] SYN 을 검사는 하는가
flood 300
sleep 2
seen=$(grep -aoE 'SYN 검사: [0-9]+' /tmp/11xdp.txt | grep -oE '[0-9]+' | sort -n | tail -1); seen=${seen:-0}
[ "$seen" -gt 0 ] && card 20 1 "SYN 을 검사한다" "검사 $seen" || card 20 0 "SYN 미검사"

# [4] 임계값 초과분 차단
drop=$(grep -aoE '차단: [0-9]+' /tmp/11xdp.txt | grep -oE '[0-9]+' | sort -n | tail -1); drop=${drop:-0}
[ "$drop" -gt 0 ] && card 35 1 "flood 차단" "차단 $drop 🛡️" || card 35 0 "flood 미차단" "ddos.bpf.c TODO 확인"

pkill -f bin/11-xdp-ddos 2>/dev/null

echo "──────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then printf '  \033[32m🎉 클리어!\033[0m\n'; exit 0
else printf '  \033[33m아직이다. ddos.bpf.c 의 TODO 를 채워라. (막히면 solution/)\033[0m\n'; exit 1; fi
