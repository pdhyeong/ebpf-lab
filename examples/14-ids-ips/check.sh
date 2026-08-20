#!/usr/bin/env bash
# 14번 채점 (점수제): 시그니처(EVIL) 탐지(IDS)와 차단(IPS)을 검사.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %s  %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %s  %s\n' "$3" "${4:-}"; fi
}

echo "╔═══ 14. IDS/IPS 채점 ═══╗"

go generate ./examples/14-ids-ips/ >/dev/null 2>&1
if go build -o bin/14-ids-ips ./examples/14-ids-ips 2>/tmp/14b.txt; then card 20 1 "빌드"
else card 20 0 "빌드" "$(head -1 /tmp/14b.txt)"; echo 중단; exit 1; fi

send() { printf '%s' "$1" | nc -u -w1 127.0.0.1 9999 2>/dev/null; }

# ---- IDS 모드: 매치 경보가 떠야 하고, 서버는 여전히 받아야 한다 ----
pkill -f bin/14-ids-ips 2>/dev/null; pkill -x nc 2>/dev/null; sleep 0.5
( timeout 9 ./bin/14-ids-ips -iface lo -mode ids > /tmp/14ids.txt 2>&1 & )
sleep 2
( timeout 5 nc -u -l 9999 > /tmp/14srv_ids.txt 2>&1 & )
sleep 0.5
send "hello-EVIL-here"; sleep 0.3; send "clean-normal"
sleep 2.5
pkill -f bin/14-ids-ips 2>/dev/null; pkill -x nc 2>/dev/null; sleep 1
hit=$(grep -aoE '매치: [0-9]+' /tmp/14ids.txt | grep -oE '[0-9]+' | sort -n | tail -1); hit=${hit:-0}
[ "$hit" -gt 0 ] && card 40 1 "IDS: EVIL 시그니처 탐지" "매치 $hit 🚨" || card 40 0 "IDS: 미탐지" "ids.bpf.c TODO 확인"
grep -q EVIL /tmp/14srv_ids.txt && card 15 1 "IDS: 정상 배달(탐지만, 차단X)" || card 15 0 "IDS 인데 배달이 막힘"

# ---- IPS 모드: 서버가 EVIL 을 못 받아야 한다 ----
pkill -f bin/14-ids-ips 2>/dev/null; pkill -x nc 2>/dev/null; sleep 0.5
( timeout 9 ./bin/14-ids-ips -iface lo -mode ips > /tmp/14ips.txt 2>&1 & )
sleep 2
( timeout 5 nc -u -l 9999 > /tmp/14srv_ips.txt 2>&1 & )
sleep 0.5
send "block-this-EVIL"; sleep 0.3; send "clean-normal"
sleep 2.5
pkill -f bin/14-ids-ips 2>/dev/null; pkill -x nc 2>/dev/null; sleep 1
blk=$(grep -aoE '차단: [0-9]+' /tmp/14ips.txt | grep -oE '[0-9]+' | sort -n | tail -1); blk=${blk:-0}
if grep -q EVIL /tmp/14srv_ips.txt; then card 25 0 "IPS: EVIL 이 배달됨(차단 실패)"
else [ "$blk" -gt 0 ] && card 25 1 "IPS: EVIL 차단(서버 미배달)" "차단 $blk 🛡️" || card 25 0 "IPS: 차단 0"; fi

pkill -f bin/14-ids-ips 2>/dev/null; pkill -x nc 2>/dev/null
echo "──────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then printf '  \033[32m🎉 클리어! IDS 탐지 + IPS 차단.\033[0m\n'; exit 0
else printf '  \033[33m아직이다. ids.bpf.c 의 TODO 를 채워라. (막히면 solution/)\033[0m\n'; exit 1; fi
