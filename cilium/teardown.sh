#!/usr/bin/env bash
# kind + Cilium 실습 클러스터 삭제.
# setup.sh 가 저장해 둔 원래 kubectl 컨텍스트로 되돌린다.
set -euo pipefail

CLUSTER=cilium-lab
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREV_CTX_FILE="$HERE/.prev-context"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "kind 클러스터 $CLUSTER 삭제 중..."
  kind delete cluster --name "$CLUSTER"
else
  echo "클러스터 $CLUSTER 가 없다."
fi

# 실습 전에 쓰던 컨텍스트 복구
if [ -f "$PREV_CTX_FILE" ]; then
  prev="$(cat "$PREV_CTX_FILE")"
  if kubectl config get-contexts -o name 2>/dev/null | grep -qx "$prev"; then
    kubectl config use-context "$prev" >/dev/null
    echo "kubectl 컨텍스트를 $prev 로 되돌렸다."
  else
    echo "이전 컨텍스트 $prev 를 더 이상 찾을 수 없다. 수동으로 전환할 것."
  fi
  rm -f "$PREV_CTX_FILE"
fi

echo "완료."
