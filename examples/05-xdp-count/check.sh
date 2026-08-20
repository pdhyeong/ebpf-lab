#!/usr/bin/env bash
# 05번 채점 (점수제): XDP 가 IPv4 트래픽을 프로토콜별로 세는지 검사.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %s  %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %s  %s\n' "$3" "${4:-}"; fi
}

echo "╔═══ 05. XDP 프로토콜 집계 채점 ═══╗"

go generate ./examples/05-xdp-count/ >/dev/null 2>&1
if go build -o bin/05-xdp-count ./examples/05-xdp-count 2>/tmp/05b.txt; then card 20 1 "빌드"
else card 20 0 "빌드" "$(head -1 /tmp/05b.txt)"; echo 중단; exit 1; fi

pkill -f bin/05-xdp-count 2>/dev/null; sleep 0.5
( timeout 9 ./bin/05-xdp-count -iface lo > /tmp/05.txt 2>&1 & )
sleep 2
# ICMP + TCP 트래픽 발생 (loopback)
ping -c3 -W1 127.0.0.1 >/dev/null 2>&1
timeout 0.05 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>/dev/null || true
timeout 0.05 bash -c 'exec 3<>/dev/tcp/127.0.0.1/59999' 2>/dev/null || true
sleep 3
pkill -f bin/05-xdp-count 2>/dev/null; sleep 1

grep -qa "ICMP" /tmp/05.txt && card 40 1 "ICMP 카운트" || card 40 0 "ICMP 미집계" "xdp.bpf.c TODO 확인"
grep -qa "TCP" /tmp/05.txt && card 40 1 "TCP 카운트" || card 40 0 "TCP 미집계" "xdp.bpf.c TODO 확인"

echo "──────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then printf '  \033[32m🎉 클리어! XDP 가 IPv4 를 집계한다.\033[0m\n'; exit 0
else printf '  \033[33m아직이다. examples/05-xdp-count/xdp.bpf.c 의 TODO 를 채워라. (막히면 solution/)\033[0m\n'; exit 1; fi
