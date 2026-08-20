#!/usr/bin/env bash
# kind + Cilium 실습 클러스터 구축.
#
#   ./cilium/setup.sh            대화형 (필요한 도구 설치 여부를 물어본다)
#   AUTO=1 ./cilium/setup.sh     묻지 않고 진행
#
# 만드는 것:
#   - kind 클러스터 cilium-lab (control-plane 1 + worker 2), 기본 CNI/kube-proxy 없음
#   - Cilium (kube-proxy 대체 = eBPF 로드밸런서, Hubble 관측)
#   - Star Wars 데모 앱 (L3/L4 + L7 네트워크 정책 실습용)
set -euo pipefail

CLUSTER=cilium-lab
# 기본값은 Cilium 이 공지하는 stable 버전을 그때그때 가져온다.
# 네트워크가 안 되면 아래 고정값으로 떨어진다.
CILIUM_VERSION="${CILIUM_VERSION:-$(curl -fsSL --max-time 5 https://raw.githubusercontent.com/cilium/cilium/main/stable.txt 2>/dev/null | tr -d 'v[:space:]')}"
CILIUM_VERSION="${CILIUM_VERSION:-1.20.0}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '\n\033[1;34m==>\033[0m \033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
die()  { printf '\n\033[31m오류:\033[0m %s\n' "$1" >&2; exit 1; }

confirm() {
  [ "${AUTO:-0}" = "1" ] && return 0
  read -r -p "  $1 [y/N] " a
  [[ "$a" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------- 사전 점검
info "1. 사전 요구사항 점검"

docker info >/dev/null 2>&1 || die "Docker 가 실행 중이 아니다. Docker Desktop 을 먼저 켜라."
ok "docker $(docker version --format '{{.Server.Version}}')"

missing=()
for t in kubectl kind cilium; do
  command -v "$t" >/dev/null 2>&1 || missing+=("$t")
done

if [ ${#missing[@]} -gt 0 ]; then
  printf '  없는 도구: %s\n' "${missing[*]}"
  brew_pkgs=()
  for t in "${missing[@]}"; do
    case "$t" in
      kubectl) brew_pkgs+=(kubectl) ;;
      kind)    brew_pkgs+=(kind) ;;
      cilium)  brew_pkgs+=(cilium-cli) ;;
    esac
  done
  if command -v brew >/dev/null 2>&1; then
    echo "  설치 명령: brew install ${brew_pkgs[*]}"
    if confirm "지금 설치할까?"; then
      brew install "${brew_pkgs[@]}"
    else
      die "위 명령을 직접 실행한 뒤 다시 시도해라."
    fi
  else
    die "Homebrew 가 없다. 수동 설치: https://kind.sigs.k8s.io/ , https://github.com/cilium/cilium-cli"
  fi
fi
for t in kubectl kind cilium; do ok "$t $(command -v "$t")"; done

# Docker Desktop 메모리 확인 (Cilium + 3노드는 최소 6GB 정도가 편하다)
mem_bytes=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
mem_gb=$(( mem_bytes / 1024 / 1024 / 1024 ))
if [ "$mem_gb" -lt 6 ]; then
  printf '  \033[33m경고\033[0m Docker Desktop 메모리가 %dGB 다. 설정에서 6GB 이상 권장.\n' "$mem_gb"
else
  ok "Docker 메모리 ${mem_gb}GB"
fi

# ---------------------------------------------------------------- 클러스터
info "2. kind 클러스터 ($CLUSTER)"

# kind 는 클러스터를 만들면서 현재 kubectl 컨텍스트를 자기 것으로 바꿔 버린다.
# 원래 쓰던 컨텍스트(운영 클러스터일 수 있다)를 기억해 뒀다가 teardown 때 되돌린다.
PREV_CTX_FILE="$HERE/.prev-context"
if [ ! -f "$PREV_CTX_FILE" ]; then
  prev="$(kubectl config current-context 2>/dev/null || true)"
  case "$prev" in
    ""|"kind-$CLUSTER") : ;;
    *) printf '%s\n' "$prev" > "$PREV_CTX_FILE"
       printf '  \033[33m주의\033[0m 현재 컨텍스트 %s 를 %s 에 저장했다.\n' "$prev" "$PREV_CTX_FILE"
       printf '        실습이 끝나면 make cilium-down 이 자동으로 되돌린다.\n' ;;
  esac
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  ok "이미 존재한다 (다시 만들려면: ./cilium/teardown.sh)"
else
  kind create cluster --config "$HERE/kind-config.yaml"
fi
kubectl cluster-info --context "kind-$CLUSTER" >/dev/null
kubectl config use-context "kind-$CLUSTER" >/dev/null
ok "컨텍스트: kind-$CLUSTER"

echo
echo "  CNI 가 없으니 노드는 NotReady 상태여야 정상이다:"
kubectl get nodes

# ---------------------------------------------------------------- Cilium
info "3. Cilium $CILIUM_VERSION 설치"
if kubectl -n kube-system get ds cilium >/dev/null 2>&1; then
  ok "이미 설치되어 있다"
else
  # kube-proxy 를 없앴으므로 Cilium 이 API 서버를 직접 찾아갈 주소를 알려줘야 한다.
  # kind 에서는 control-plane 컨테이너 이름이 클러스터 내부에서 해석된다.
  cilium install \
    --version "$CILIUM_VERSION" \
    --set kubeProxyReplacement=true \
    --set k8sServiceHost="${CLUSTER}-control-plane" \
    --set k8sServicePort=6443 \
    --set ipam.mode=kubernetes \
    --set operator.replicas=1 \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=true \
    --set bpf.masquerade=true \
    --set image.pullPolicy=IfNotPresent
fi

info "4. Cilium 기동 대기 (수 분 걸릴 수 있다)"
cilium status --wait --wait-duration 5m
kubectl get nodes

# ---------------------------------------------------------------- DNS 보정
info "5. 클러스터 DNS 업스트림 보정"
# Docker Desktop 의 내부 리졸버(192.168.65.254)는 kind 노드의 호스트 netns 에서는
# 응답하지만 파드 네트워크에서는 응답하지 않는다. coredns 가 그쪽으로 포워딩하도록
# 두면 클러스터 안에서 외부 이름이 전부 SERVFAIL 이 되고, DNS 기반 egress 정책
# 실습(policies/03-dns-egress.yaml)이 불가능해진다.
cur="$(kubectl -n kube-system get cm coredns -o jsonpath='{.data.Corefile}')"
if printf '%s' "$cur" | grep -q 'forward \. /etc/resolv.conf'; then
  new_corefile="$(printf '%s' "$cur" | sed 's#forward \. /etc/resolv.conf#forward . 1.1.1.1 8.8.8.8#')"
  kubectl -n kube-system create cm coredns --from-literal=Corefile="$new_corefile" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
  kubectl -n kube-system rollout restart deploy/coredns >/dev/null
  kubectl -n kube-system rollout status deploy/coredns --timeout=120s >/dev/null
  ok "coredns 업스트림을 1.1.1.1 / 8.8.8.8 로 변경"
else
  ok "coredns 업스트림 이미 변경됨"
fi

# ---------------------------------------------------------------- 데모 앱
info "6. Star Wars 데모 앱 배포"
kubectl apply -f "$HERE/manifests/starwars.yaml"
kubectl wait --for=condition=Ready pod -l 'org in (empire, alliance)' --timeout=180s
kubectl get pods -o wide -l 'org in (empire, alliance)'

# ---------------------------------------------------------------- 마무리
# ---------------------------------------------------------------- 자체 검증
info "7. 동작 검증"
for i in $(seq 1 10); do
  if kubectl exec xwing -- curl -s -m 5 -XPOST \
       deathstar.default.svc.cluster.local/v1/request-landing 2>/dev/null | grep -q "Ship landed"; then
    ok "파드 간 통신 정상 (정책 없음 = 둘 다 착륙 가능)"; break
  fi
  [ "$i" = 10 ] && printf '  \033[33m경고\033[0m 데모 앱 통신 확인 실패. kubectl get pods 로 상태 확인.\n'
  sleep 3
done
if kubectl exec tiefighter -- curl -s -m 8 -o /dev/null \
     -w '%{http_code}' http://example.com 2>/dev/null | grep -q 200; then
  ok "클러스터 외부 통신/DNS 정상"
else
  printf '  \033[33m경고\033[0m 외부 DNS 확인 실패. coredns 로그를 볼 것.\n'
fi

info "완료"
cat <<'EOF'
  다음으로 볼 것:

    kubectl get pods -A                          클러스터 상태
    cilium status                                Cilium 요약
    cilium connectivity test                     공식 연결성 테스트 (10분 정도)

    # Cilium 이 만든 실제 BPF 프로그램/맵 보기
    make cilium-bpf

    # kube-proxy 없이 Service 가 어떻게 처리되는지 (BPF 로드밸런서 테이블)
    make cilium-lb

    # 실습 과제
    open cilium/exercises.md
EOF

if [ -f "$PREV_CTX_FILE" ]; then
  printf '\n  \033[33m컨텍스트가 kind-%s 로 바뀌었다.\033[0m 원래 클러스터로 돌아가려면:\n' "$CLUSTER"
  printf '    kubectl config use-context %s\n\n' "$(cat "$PREV_CTX_FILE")"
fi
