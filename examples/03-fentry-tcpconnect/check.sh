#!/usr/bin/env bash
# 03번 채점 (단계별 점수제): fentry/fexit 로 tcp_connect 를 관측하는지.
#   Lv1 이벤트/호출수 -> Lv2 CO-RE 주소·포트 -> Lv3 IPv6 분기 + fexit -> Lv4 필터(보너스)
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
  printf '  \033[32m🎉 클리어! kprobe 의 자유도 + tracepoint 의 안전성을 동시에 얻었다.\033[0m\n'
  printf '  다음: examples/03-fentry-tcpconnect/STUDY.html (이론 + OX 퀴즈) → make 04\n'
  exit 0
else
  printf '  \033[33m아직이다. tcpconnect.bpf.c 의 TODO 를 순서대로 채워라. (막히면 solution/)\033[0m\n'
  exit 1
fi
}

echo "╔═══ 03. fentry/fexit tcp_connect 채점 ═══╗"

go generate ./examples/03-fentry-tcpconnect/ >/dev/null 2>&1
if go build -o bin/03-fentry-tcpconnect ./examples/03-fentry-tcpconnect 2>/tmp/03b.txt; then
  card 5 1 "Lv0-a 빌드"
else
  card 5 0 "Lv0-a 빌드 실패" "$(head -3 /tmp/03b.txt | tr '\n' ' ')"
  echo "  → fentry 는 시그니처가 틀리면 verifier 가 거부한다. 인자 타입을 확인하라."
  exit 1
fi

PORT=59998
pkill -f bin/03-fentry-tcpconnect 2>/dev/null; sleep 0.5
( timeout 11 ./bin/03-fentry-tcpconnect > /tmp/03.txt 2>&1 & )
sleep 2.5
# IPv4 연결 시도 (거부돼도 tcp_connect 는 호출된다)
for i in 1 2 3; do timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null || true; done
# IPv6 연결 시도
for i in 1 2; do timeout 1 bash -c 'exec 3<>/dev/tcp/::1/59997' 2>/dev/null || true; done
sleep 3
pkill -f bin/03-fentry-tcpconnect 2>/dev/null; sleep 1

CALLS=$(grep -aoE '누적: tcp_connect [0-9]+ 건' /tmp/03.txt | grep -oE '[0-9]+' | sort -n | tail -1); CALLS=${CALLS:-0}
V6=$(grep -aoE 'IPv6 [0-9]+' /tmp/03.txt | grep -oE '[0-9]+' | sort -n | tail -1); V6=${V6:-0}
ROWS=$(awk '$1 ~ /^[0-9]+$/ && /->/ {print}' /tmp/03.txt || true)
NROWS=$(printf '%s' "$ROWS" | grep -c . || true)

# ---------------------------------------------------------------- Lv0-b 훅 부착
if grep -aq '부착' /tmp/03.txt; then
  card 10 1 "Lv0-b 훅에 부착 성공"
else
  card 10 0 "Lv0-b 훅 부착 실패" "SEC() 을 직접 찾아 채워라"
  echo "  ↳ $(grep -am1 'unspecified\|실패\|rror' /tmp/03.txt || echo '프로그램이 부착 메시지를 출력하지 못했다')"
  echo "  → fentry 는 SEC 에 대상 함수가 들어간다. bpftrace -l 'kfunc:*tcp_connect*' 로 찾아라. fexit 도 같이."
  skip 30 "Lv1 (Lv0 먼저)"
  skip 25 "Lv2 (Lv0 먼저)"
  skip 20 "Lv3 (Lv0 먼저)"
  skip 10 "Lv4 (Lv0 먼저)"
  finish
fi

# ---------------------------------------------------------------- Lv1
if [ "${NROWS:-0}" -gt 0 ] && [ "$CALLS" -gt 0 ]; then
  card 30 1 "Lv1 fentry 이벤트 + 호출수" "이벤트 ${NROWS}건 / 호출 ${CALLS}건"
  LV1=1
else
  card 30 0 "Lv1 이벤트가 안 온다" "이벤트 ${NROWS:-0}건 / 호출 ${CALLS}건"
  echo "  → bump(STAT_CALLS), BPF_CORE_READ(family), bpf_ringbuf_reserve 확인."
  LV1=0
fi

# ---------------------------------------------------------------- Lv2
if [ "$LV1" = 1 ]; then
  if grep -aq ":$PORT" /tmp/03.txt; then
    card 25 1 "Lv2 CO-RE 주소·포트 읽기" "DST 127.0.0.1:$PORT 확인"
    LV2=1
  else
    card 25 0 "Lv2 포트가 안 맞는다" "127.0.0.1:$PORT 를 못 찾음"
    echo "  → skc_daddr/skc_dport 를 BPF_CORE_READ 로 읽고 dport 는 bpf_ntohs 하라."
    LV2=0
  fi
else
  skip 25 "Lv2 (Lv1 먼저)"; LV2=0
fi

# ---------------------------------------------------------------- Lv3
if [ "$LV2" = 1 ]; then
  if [ "$V6" -gt 0 ]; then
    card 20 1 "Lv3 IPv6 분기 + fexit" "IPv6 ${V6}건 집계"
    LV3=1
  else
    card 20 0 "Lv3 IPv6 가 0" "tcpconnect.bpf.c 의 Lv3 TODO"
    echo "  → family == AF_INET6 일 때 bump(STAT_IPV6) 가 빠졌다."
    LV3=0
  fi
else
  skip 20 "Lv3 (Lv2 먼저)"; LV3=0
fi

# ---------------------------------------------------------------- Lv4 보너스
if [ "$LV3" = 1 ]; then
  if grep -qE 'bpf_ringbuf_discard|dport != |dport == ' examples/03-fentry-tcpconnect/tcpconnect.bpf.c; then
    card 10 1 "Lv4 커널 포트 필터 (보너스)" "필터 코드 확인"
  else
    card 10 0 "Lv4 미구현 (보너스)" "모든 연결이 유저 공간으로 올라온다"
    echo "  → 선택 과제다. 관심 없는 포트는 reserve 전에 return 하거나 discard 하라."
  fi
else
  skip 10 "Lv4 (보너스, Lv3 먼저)"
fi


finish
