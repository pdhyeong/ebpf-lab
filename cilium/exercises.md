# Cilium 실습 과제

**클러스터는 이미 떠 있다.** (`make cilium-up` 으로 다시 만들 수 있다)
아래 과제를 순서대로 진행하면 된다. 각 과제는 "무엇을 보는지" 와
"왜 그게 중요한지" 를 같이 적었고, 여기 붙은 출력은 전부 실제로 나온 것이다.

현재 구성: kind v0.32.0 / k8s v1.36.1 (3노드) / **Cilium v1.20.0** /
kube-proxy 없음 / Hubble 활성화 / Star Wars 데모 앱 배포됨.

## 시작 전 두 가지

**1. kubectl 컨텍스트가 `kind-cilium-lab` 로 바뀌어 있다.**
원래 쓰던 컨텍스트는 `cilium/.prev-context` 에 저장돼 있고
`make cilium-down` 이 자동 복구한다.

```bash
make cilium-ctx     # 지금 어느 클러스터를 보고 있는지
```

**2. `hubble` CLI 가 relay 보다 버전이 낮다는 경고가 뜬다.**
brew 의 hubble 은 v1.19.4, 클러스터의 relay 는 v1.20.0 이다. 기능은 정상
동작하니 무시해도 된다. 거슬리면 `2>/dev/null` 로 넘기면 된다.

---

## 0. 클러스터가 진짜 eBPF 로 돌고 있는지 확인

```bash
cilium status
kubectl -n kube-system get pods -l k8s-app=cilium -o wide
```

`KubeProxyReplacement: True` 인지 본다. True 면 Service ClusterIP 처리가
iptables 가 아니라 BPF 맵으로 이뤄지고 있다는 뜻이다. 실제 출력:

```
KubeProxyReplacement:    True   [eth0  172.21.0.2 ... (Direct Routing)]
Routing:                 Network: Tunnel [vxlan]   Host: BPF
Masquerading:            BPF   [eth0]   10.244.0.0/24
Cluster Pods:            9/9 managed by Cilium
```

```bash
# kube-proxy 가 정말 없는지
kubectl -n kube-system get ds | grep -i proxy || echo "kube-proxy 없음 (정상)"

# 에이전트 내부에서 본 상세 상태
POD=$(kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1)
kubectl -n kube-system exec $POD -c cilium-agent -- cilium-dbg status | head -20
```

**포인트**: 노드 수 x 서비스 수 만큼 늘어나던 iptables 체인이 사라진다.
서비스가 수천 개인 클러스터에서 kube-proxy 의 규칙 갱신 지연이 문제가 되는데,
BPF 맵은 O(1) 해시 조회라 서비스 수에 따라 지연이 늘지 않는다.

---

## 1. Cilium 이 로드한 BPF 프로그램과 맵을 직접 본다

```bash
make cilium-bpf      # cilium-agent 파드 안에서 bpftool 실행
```

또는 직접:

```bash
POD=$(kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1)
kubectl -n kube-system exec $POD -c cilium-agent -- bpftool prog list | grep 'name cil_'
kubectl -n kube-system exec $POD -c cilium-agent -- ls /sys/fs/bpf/tc/globals/
```

실제로 이 노드에는 **커널 전체 BPF 프로그램 375개 중 Cilium 소속(`cil_*`)이 93개**,
pin 된 맵이 **38개** 있다:

```
cilium_ct4_global          conntrack 테이블
cilium_lb4_backends_v3     로드밸런서 백엔드
cilium_lb4_maglev          Maglev 해싱 테이블 (일관성 있는 백엔드 선택)
cilium_ipcache_v2          IP -> identity 매핑
cilium_call_policy         정책 판정용 tail call 맵
cilium_auth_map            mTLS/인증 상태
...
```

**주의해서 볼 것**: `bpftool prog list` 에 Cilium 것이 아닌 프로그램도 잔뜩 나온다.
kind 노드는 컨테이너라서 **호스트 커널을 공유**하기 때문이다. 그래서 이 랩의
`ebpf-lab` 컨테이너에서 돌린 01~07번 프로그램도, 맥에서 돌고 있는 다른
컨테이너의 BPF 프로그램도 같은 목록에 섞여 나온다. 커널은 하나뿐이다.

**포인트**: 우리가 07번 예제에서 `-pin` 옵션으로 한 그 pinning 이다.
Cilium 은 agent 가 재시작되어도 데이터패스가 살아 있어야 하므로
모든 상태를 bpffs 에 pin 해 둔다. 이게 "무중단 업그레이드" 의 기반이다.

---

## 2. Service 로드밸런싱 테이블 = BPF 맵

```bash
make cilium-lb
```

또는:

```bash
POD=$(kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1)
kubectl -n kube-system exec -it $POD -- cilium-dbg bpf lb list
kubectl -n kube-system exec -it $POD -- cilium-dbg bpf ct list global | head -20
```

`deathstar` 서비스의 ClusterIP 와 그 뒤의 파드 IP 2개가 매핑되어 있다. 실제 출력:

```
SERVICE ADDRESS             BACKEND ADDRESS (REVNAT_ID) (SLOT)
10.96.105.150:80/TCP (1)    10.244.1.8:80/TCP (8) (1)        <- deathstar
10.96.0.1:443/TCP (1)       172.21.0.2:6443/TCP (7) (1)      <- kubernetes API
10.96.0.10:53/UDP (1)       10.244.2.163:53/UDP (5) (1)      <- kube-dns
```
파드를 하나 지우고 다시 보면 테이블이 갱신된다.

```bash
kubectl delete pod -l class=deathstar --wait=false
sleep 15
kubectl -n kube-system exec -it $POD -- cilium-dbg bpf lb list
```

**포인트**: `cilium-dbg bpf lb list` 는 결국 BPF 맵 덤프다.
`bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_lb4_services_v2` 와
같은 데이터를 사람이 읽기 좋게 보여주는 것.

---

## 3. 라벨 -> identity -> BPF 정책 맵

```bash
POD=$(kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1)
kubectl -n kube-system exec -it $POD -- cilium-dbg identity list
kubectl -n kube-system exec -it $POD -- cilium-dbg endpoint list
```

실제 출력 (`make cilium-identity`):

```
ID      LABELS
1       reserved:host
2       reserved:world
3049    k8s:class=xwing
21579   k8s:class=deathstar
57516   k8s:class=tiefighter
```

**포인트**: Cilium 은 라벨 조합을 숫자 identity 로 압축한다.
BPF 프로그램은 문자열 비교를 못 하니까 (그리고 하면 느리니까),
정책 판단은 "identity 숫자 + 포트" 로 BPF 맵을 조회하는 형태가 된다.
정책을 IP 가 아니라 라벨로 쓸 수 있는 이유가 이 간접층이다.

---

## 4. L3/L4 네트워크 정책

정책 적용 전, 둘 다 성공하는 것을 확인:

```bash
kubectl exec xwing      -- curl -s -m 3 -XPOST deathstar.default.svc.cluster.local/v1/request-landing
kubectl exec tiefighter -- curl -s -m 3 -XPOST deathstar.default.svc.cluster.local/v1/request-landing
```

정책 적용:

```bash
kubectl apply -f cilium/policies/01-l3-l4.yaml
kubectl exec xwing      -- curl -s -m 3 -XPOST deathstar.default.svc.cluster.local/v1/request-landing; echo "exit=$?"
kubectl exec tiefighter -- curl -s -m 3 -XPOST deathstar.default.svc.cluster.local/v1/request-landing
```

위 두 단계를 한 번에 보고 싶으면: `make cilium-demo`

실제 결과 — xwing 은 curl exit 28(타임아웃)이 되고 tiefighter 만 성공한다.
"connection refused" 가 아니라 **타임아웃**인 게 핵심이다. RST 조차 돌아오지
않는다는 건 패킷이 커널에서 그냥 사라졌다는 뜻이다.

드롭 관찰:

```bash
make hubble &                         # 별도 터미널이면 그냥 make hubble
hubble observe --verdict DROPPED --last 20
```

실제 출력:

```
default/xwing:56376 (ID:3049) <> default/deathstar-...:80 (ID:21579) \
  policy-verdict:none TRAFFIC_DIRECTION_UNKNOWN DENIED (TCP Flags: SYN)
default/xwing:56376 (ID:3049) <> default/deathstar-...:80 (ID:21579) \
  Policy denied DROPPED (TCP Flags: SYN)
```

**여기서 3번 과제와 연결된다.** 판정에 쓰인 건 IP 가 아니라 `ID:3049`(xwing) 와
`ID:21579`(deathstar) 라는 identity 숫자다. 파드가 재시작해 IP 가 바뀌어도
라벨이 같으면 identity 가 같으므로 정책은 그대로 동작한다.

**포인트**: xwing 은 커널에서 드롭된다. 유저 공간까지 오지 않는다.
`hubble observe` 가 보여주는 건 BPF 프로그램이 링버퍼로 올린 이벤트다.
우리가 01/07번 예제에서 만든 그 구조와 동일하다.

---

## 5. L7 HTTP 정책과 그 비용

```bash
kubectl apply -f cilium/policies/02-l7-http.yaml

kubectl exec tiefighter -- curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
# -> Ship landed

kubectl exec tiefighter -- curl -s -XPUT deathstar.default.svc.cluster.local/v1/exhaust-port
# -> Access denied

hubble observe --pod tiefighter --protocol http --last 10
```

실제 출력 — L4 정책만 있을 때는 절대 안 보이던 HTTP 레벨 이벤트가 나온다:

```
-> deathstar:80 http-request  FORWARDED (HTTP/1.1 POST .../v1/request-landing)
<- deathstar:80 http-response FORWARDED (HTTP/1.1 200 13ms (POST .../v1/request-landing))
-> deathstar:80 http-request  DROPPED   (HTTP/1.1 PUT  .../v1/exhaust-port)
<- deathstar:80 http-response FORWARDED (HTTP/1.1 403 0ms (PUT .../v1/exhaust-port))
```

`http-request DROPPED` 다음에 `403` 응답이 FORWARDED 로 이어지는 게 보인다.
요청은 백엔드에 도달하지 못했고, 403 은 프록시가 대신 만들어 돌려준 것이다.

**포인트**: 403 은 BPF 가 만든 게 아니라 Envoy 가 만든 응답이다.
L7 정책이 붙은 포트의 트래픽은 프록시를 경유하므로 지연이 늘고,
Envoy 메모리도 파드마다 붙는다. 그래서 실무에서는

- L3/L4 로 충분한 곳은 L4 로 끝낸다
- L7 은 정말 필요한 경로에만 좁게 적용한다

를 원칙으로 잡는다.

---

## 6. DNS 기반 egress 정책 (실무에서 가장 많이 쓰는 형태)

```bash
kubectl apply -f cilium/policies/03-dns-egress.yaml

kubectl exec tiefighter -- curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://example.com
kubectl exec tiefighter -- curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://github.com   # 실패해야 정상

POD=$(kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1)
kubectl -n kube-system exec -it $POD -- cilium-dbg fqdn cache list
hubble observe --pod tiefighter --protocol dns --last 20
```

실제 결과: `example.com` 은 200, `github.com` 은 타임아웃.
`make cilium-fqdn` 으로 학습된 캐시를 보면:

```
Endpoint  Source  FQDN          TTL  IPs
3764      lookup  example.com.  14   172.66.147.243,104.20.23.154
3764      lookup  github.com.   30   20.200.245.247
```

github.com 도 **캐시에는 있다**. DNS 질의 자체는 허용했기 때문이다.
다만 그 IP 가 정책 맵에 들어가지 않아서 실제 연결이 드롭된다.
"이름을 물어보는 것" 과 "그 주소로 나가는 것" 이 별개의 허가라는 뜻이다.

**포인트**: 외부 서비스 IP 는 계속 바뀐다. Cilium 은 DNS 응답을 학습해서
그 IP 를 정책 맵에 임시로 넣어 준다. TTL 이 지나면 빠진다.
이 방식의 한계도 알아 둬야 한다 - 파드가 DNS 를 안 쓰고 하드코딩된 IP 로
직접 접속하면 이 정책은 무력하다.

### 이 과제를 만들면서 실제로 걸렸던 문제

처음에는 `example.com` 도 실패했다. 원인은 정책이 아니라 **클러스터 DNS** 였다.

kind 노드의 `/etc/resolv.conf` 는 Docker Desktop 내부 리졸버 `192.168.65.254` 를
가리키는데, 이 주소는 노드의 호스트 netns 에서는 응답하지만 **파드 네트워크에서는
응답하지 않는다.** coredns 가 거기로 포워딩하니 클러스터 안의 모든 외부 이름이
SERVFAIL 이 됐다. `setup.sh` 가 coredns 업스트림을 `1.1.1.1 / 8.8.8.8` 로 바꾼다.

디버깅 순서가 중요하다 — "DNS 가 안 된다" 를 만나면:

```bash
# 1) 파드 egress 자체가 죽었나? (DNS 안 쓰고 IP 로 직접)
kubectl exec xwing -- curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://1.1.1.1
#    301 이 나오면 egress 는 멀쩡하다 -> DNS 문제로 좁혀진다

# 2) coredns 가 업스트림에 못 가는 건가?
kubectl -n kube-system logs -l k8s-app=kube-dns --tail=20 | grep -i error
#    "i/o timeout ...->192.168.65.254:53" 이면 업스트림 문제

# 3) hubble 로 DNS 프록시 동작 확인
hubble observe --pod tiefighter --protocol dns --last 20
```

이 세 단계를 안 나누면 "Cilium 정책이 DNS 를 막았다" 고 오진하기 딱 좋다.
실제로는 정책은 정상 동작(`dns-request proxy FORWARDED`)하고 있었고,
coredns 가 `Server Failure` 를 돌려주고 있었다.

---

## 7. 정리 후 다음 단계

```bash
kubectl delete -f cilium/policies/ --ignore-not-found
cilium connectivity test          # 공식 회귀 테스트 (10분 내외)
```

더 볼 것:

- `cilium monitor` — 데이터패스 이벤트 원본 스트림 (`hubble` 의 하위 계층)
- `cilium-dbg bpf ct list global` — conntrack 테이블. BPF 맵으로 구현된 커넥션 추적
- Cilium 소스의 `bpf/bpf_lxc.c` — 파드에 붙는 실제 데이터패스 프로그램.
  01~06번 예제에서 쓴 문법과 완전히 같은 C 코드다
- `pkg/datapath/loader` — Go 로 BPF 를 로드/어태치하는 부분.
  우리가 `link.AttachTCX` 로 한 것을 프로덕션 규모로 한 코드
- Tetragon — 07번 예제와 같은 구조의 런타임 보안 제품

정리:

```bash
make cilium-down
```
