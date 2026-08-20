#!/usr/bin/env bash
# 02번 채점 (단계별 점수제): tracepoint 로 openat 을 커널에서 집계하는지.
#   Lv1 맵 등록 -> Lv2 원자적 증가 -> Lv3 PERCPU 총합 -> Lv4 키 확장(보너스)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

score=0; total=0; PASS_MARK=70
card() {
  total=$((total+$1))
  if [ "$2" = 1 ]; then score=$((score+$1)); printf '  \033[32m✅ [%3d점]\033[0m %-30s %s\n' "$1" "$3" "${4:-}"
  else printf '  \033[31m⬜ [  0점]\033[0m %-30s %s\n' "$3" "${4:-}"; fi
}
skip() { total=$((total+$1)); printf '  \033[90m⏭  [  0점] %-30s %s\033[0m\n' "$2" "${3:-}"; }

echo "╔═══ 02. tracepoint openat 집계 채점 ═══╗"

# ---------------------------------------------------------------- Lv0 빌드
go generate ./examples/02-tracepoint-openat/ >/dev/null 2>&1
if go build -o bin/02-tracepoint-openat ./examples/02-tracepoint-openat 2>/tmp/02b.txt; then
  card 15 1 "Lv0 빌드"
else
  card 15 0 "Lv0 빌드 실패" "$(head -3 /tmp/02b.txt | tr '\n' ' ')"
  exit 1
fi

# ---------------------------------------------------------------- 시나리오
TAG="/tmp/ebpflab02-$$"
: > "$TAG"
pkill -f bin/02-tracepoint-openat 2>/dev/null; sleep 0.5
( timeout 11 ./bin/02-tracepoint-openat > /tmp/02.txt 2>&1 & )
sleep 2
# 부하 발생: 한 bash 프로세스가 openat 을 800회 호출한다
bash -c "for i in \$(seq 800); do : < $TAG; done" 2>/dev/null
sleep 1
# 프로그램이 살아 있는 동안 커널 쪽 맵을 확인 (Lv4 용)
MAPKEY=$(bpftool map list 2>/dev/null | grep -A1 'name counts' | grep -oE 'key [0-9]+B' | tail -1 | grep -oE '[0-9]+' || true)
sleep 2
pkill -f bin/02-tracepoint-openat 2>/dev/null; sleep 1
rm -f "$TAG"

# 데이터 행: "PID COMM COUNT"
ROWS=$(awk '$1 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {print}' /tmp/02.txt || true)
NROWS=$(printf '%s' "$ROWS" | grep -c . || true)
MAXCNT=$(printf '%s\n' "$ROWS" | awk '$3+0>m {m=$3+0} END {print m+0}')
SUMTOTAL=$(grep -aoE '누적 openat 호출 [0-9]+ 건' /tmp/02.txt | grep -oE '[0-9]+' | sort -n | tail -1)
SUMTOTAL=${SUMTOTAL:-0}

# ---------------------------------------------------------------- Lv1
if [ "${NROWS:-0}" -gt 0 ]; then
  card 30 1 "Lv1 해시맵에 프로세스 등록" "프로세스 ${NROWS}종 집계"
  LV1=1
else
  card 30 0 "Lv1 집계가 전혀 안 된다" "openat.bpf.c 의 Lv1 TODO"
  echo "  → key 채우기 + bpf_map_update_elem() 이 빠졌다."
  LV1=0
fi

# ---------------------------------------------------------------- Lv2
if [ "$LV1" = 1 ]; then
  if [ "${MAXCNT:-0}" -gt 5 ]; then
    card 25 1 "Lv2 원자적 카운터 증가" "최대 카운트 ${MAXCNT}"
    LV2=1
  else
    card 25 0 "Lv2 카운트가 1에서 멈춘다" "최대 카운트 ${MAXCNT:-0}"
    echo "  → __sync_fetch_and_add(cnt, 1); 이 빠졌다. 새 항목만 넣고 증가를 안 한다."
    LV2=0
  fi
else
  skip 25 "Lv2 (Lv1 먼저)"; LV2=0
fi

# ---------------------------------------------------------------- Lv3
if [ "$LV2" = 1 ]; then
  if [ "$SUMTOTAL" -gt 0 ]; then
    card 20 1 "Lv3 PERCPU 전역 카운터" "누적 ${SUMTOTAL}건"
    LV3=1
  else
    card 20 0 "Lv3 누적 총합이 0" "openat.bpf.c 의 Lv3 TODO"
    echo "  → total 맵 lookup 후 (*cnt)++ 가 빠졌다. PERCPU 라 원자 연산은 불필요."
    LV3=0
  fi
else
  skip 20 "Lv3 (Lv2 먼저)"; LV3=0
fi

# ---------------------------------------------------------------- Lv4 보너스
if [ "$LV3" = 1 ]; then
  if [ "${MAPKEY:-20}" -ge 24 ]; then
    card 10 1 "Lv4 키에 UID 추가 (보너스)" "맵 키 ${MAPKEY}B"
  else
    card 10 0 "Lv4 미구현 (보너스)" "맵 키 ${MAPKEY:-20}B (목표 24B)"
    echo "  → 선택 과제다. struct proc_key 에 __u32 uid 를 넣고 make generate."
  fi
else
  skip 10 "Lv4 (보너스, Lv3 먼저)"
fi

echo "──────────────────────────────────────────────"
printf '  점수: \033[1m%d/%d\033[0m   (통과 기준 %d점)\n' "$score" "$total" "$PASS_MARK"
if [ "$score" -ge "$PASS_MARK" ]; then
  printf '  \033[32m🎉 클리어! 커널 안에서 집계해 경계 통과를 초당 1회로 줄였다.\033[0m\n'
  printf '  다음: examples/02-tracepoint-openat/STUDY.html (이론 + OX 퀴즈) → make 03\n'
  exit 0
else
  printf '  \033[33m아직이다. openat.bpf.c 의 TODO 를 순서대로 채워라. (막히면 solution/)\033[0m\n'
  exit 1
fi
