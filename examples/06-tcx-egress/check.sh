#!/usr/bin/env bash
# 06번 채점 (단계별 점수제): TCX 로 ingress/egress 를 집계하는지.
#   Lv1 패킷/바이트 -> Lv2 프로토콜 분류 -> Lv3 egress 방향 -> Lv4 포트 필터(보너스)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %-30s %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %-30s %s\n' "$3" "${4:-}"; fi
}
skip() { total=$((total+$1)); printf '  \033[90m⏭  [  0점] %-30s %s\033[0m\n' "$2" "${3:-}"; }

echo "╔═══ 06. TCX ingress/egress 집계 채점 ═══╗"

go generate ./examples/06-tcx-egress/ >/dev/null 2>&1
if go build -o bin/06-tcx-egress ./examples/06-tcx-egress 2>/tmp/06b.txt; then
  card 15 1 "Lv0 빌드"
else
  card 15 0 "Lv0 빌드 실패" "$(head -3 /tmp/06b.txt | tr '\n' ' ')"; exit 1
fi

pkill -f bin/06-tcx-egress 2>/dev/null; sleep 0.5
( timeout 11 ./bin/06-tcx-egress -iface lo > /tmp/06.txt 2>&1 & )
sleep 2.5
ping -c4 -W1 127.0.0.1 >/dev/null 2>&1
for i in 1 2 3; do timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/59996' 2>/dev/null || true; done
sleep 3
pkill -f bin/06-tcx-egress 2>/dev/null; sleep 1

# DIR PACKETS BYTES TCP UDP ICMP  (마지막 스냅샷에서 최대값을 뽑는다)
val() { awk -v d="$1" -v c="$2" '$1==d && $2 ~ /^[0-9]+$/ {v=$c+0; if (v>m) m=v} END {print m+0}' /tmp/06.txt; }
IN_PKT=$(val ingress 2); EG_PKT=$(val egress 2)
IN_ICMP=$(val ingress 6); IN_TCP=$(val ingress 4)

if [ "${IN_PKT:-0}" -gt 0 ]; then
  card 35 1 "Lv1 방향별 패킷/바이트" "INGRESS ${IN_PKT}패킷"
  LV1=1
else
  card 35 0 "Lv1 카운트가 전부 0" "tcx.bpf.c 의 Lv1 TODO"
  echo "  → s->packets++; s->bytes += skb->len; 이 빠졌다."
  LV1=0
fi

if [ "$LV1" = 1 ]; then
  if [ "${IN_ICMP:-0}" -gt 0 ] || [ "${IN_TCP:-0}" -gt 0 ]; then
    card 25 1 "Lv2 IPv4 프로토콜 분류" "ICMP ${IN_ICMP} / TCP ${IN_TCP}"
    LV2=1
  else
    card 25 0 "Lv2 프로토콜 분류 안 됨" "tcx.bpf.c 의 Lv2 TODO"
    echo "  → bpf_skb_load_bytes(skb, 14+9, ...) 로 IP protocol 을 읽어 switch 하라."
    LV2=0
  fi
else
  skip 25 "Lv2 (Lv1 먼저)"; LV2=0
fi

if [ "$LV2" = 1 ]; then
  if [ "${EG_PKT:-0}" -gt 0 ]; then
    card 15 1 "Lv3 egress 방향" "EGRESS ${EG_PKT}패킷"
    LV3=1
  else
    card 15 0 "Lv3 EGRESS 가 0" "tcx.bpf.c 의 Lv3 TODO"
    echo "  → tcx_egress 가 account(skb, DIR_EGRESS) 를 부르지 않는다."
    LV3=0
  fi
else
  skip 15 "Lv3 (Lv2 먼저)"; LV3=0
fi

if [ "$LV3" = 1 ]; then
  if grep -qE '14 \+ 20|dport' examples/06-tcx-egress/tcx.bpf.c; then
    card 10 1 "Lv4 포트 필터 (보너스)" "포트 파싱 확인"
  else
    card 10 0 "Lv4 미구현 (보너스)" "포트 단위 구분 없음"
  fi
else
  skip 10 "Lv4 (보너스, Lv3 먼저)"
fi

echo "──────────────────────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then
  printf '  \033[32m🎉 클리어! Cilium 데이터패스가 서 있는 바로 그 자리를 써 봤다.\033[0m\n'
  printf '  다음: examples/06-tcx-egress/STUDY.html (이론 + OX 퀴즈) → make 07\n'; exit 0
else
  printf '  \033[33m아직이다. tcx.bpf.c 의 TODO 를 순서대로 채워라. (막히면 solution/)\033[0m\n'; exit 1
fi
