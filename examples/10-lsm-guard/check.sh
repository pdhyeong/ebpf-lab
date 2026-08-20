#!/usr/bin/env bash
# 10번 채점 (점수제): "malware" 실행 차단을 여러 케이스로 검사.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %s  %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %s  %s\n' "$3" "${4:-}"; fi
}

echo "╔═══ 10. LSM 실행 차단 채점 ═══╗"

go generate ./examples/10-lsm-guard/ >/dev/null 2>&1
if go build -o bin/10-lsm-guard ./examples/10-lsm-guard 2>/tmp/10b.txt; then card 20 1 "빌드"
else card 20 0 "빌드" "$(head -1 /tmp/10b.txt)"; echo 중단; exit 1; fi

pkill -f bin/10-lsm-guard 2>/dev/null; sleep 0.5
( timeout 10 ./bin/10-lsm-guard > /tmp/10g.txt 2>&1 & )
sleep 3
cp /bin/echo /tmp/malware 2>/dev/null
cp /bin/echo /tmp/normalapp 2>/dev/null

# [1] 정상 바이너리는 실행돼야 (과잉 차단 방지)
if /tmp/normalapp ok >/dev/null 2>&1; then card 30 1 "정상 바이너리 실행 허용"
else card 30 0 "정상 실행이 막힘(과잉 차단)"; fi

# [2] malware 는 차단돼야
if /tmp/malware x >/dev/null 2>&1; then card 50 0 "malware 실행됨" "guard.bpf.c TODO 확인"
else card 50 1 "malware 실행 차단됨" "🛡️"; fi

rm -f /tmp/malware /tmp/normalapp
pkill -f bin/10-lsm-guard 2>/dev/null

echo "──────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then printf '  \033[32m🎉 클리어! LSM 가드가 실행을 차단한다.\033[0m\n'; exit 0
else printf '  \033[33m아직이다. guard.bpf.c 의 TODO 를 채워라. (막히면 solution/)\033[0m\n'; exit 1; fi
