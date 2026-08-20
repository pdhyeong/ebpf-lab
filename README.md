# eBPF + Go 실습 랩

macOS(Apple Silicon)에서 **진짜 커널에 BPF 프로그램을 로드하고 함수를 트레이싱**하는
환경이다. 에뮬레이션이나 시뮬레이션이 아니라, Docker Desktop이 돌리는 리눅스 커널에
직접 프로그램을 심는다. `cilium/ebpf`(Go)로 작성하며, Cilium 실습 클러스터까지 포함한다.

```
지금 상태:  Docker 컨테이너 2개 실행 중  +  kind 클러스터(Cilium v1.20.0) 실행 중
            학습 예제 01~07 + 보안 게임 08~14, 전부 동작 검증 완료
            바로 시작:  cd ebpf-lab && make list
```

두 갈래로 공부한다:
- **01~07 학습 트랙** — 동작하는 코드를 읽고, 고치고, 이해한다 (교재)
- **08~14 게임 트랙** — 핵심 로직을 직접 채우고 `make NN-check` 로 점수를 딴다 (실습)
  변조·차단·탐지·안티치트·백신·IDS/IPS 를 loopback 안에서 자가 검증한다.

---

## 목차

**학습 트랙 (읽고 이해)**
1. [이 랩이 뭔지, 왜 이렇게 만들었는지](#1-이-랩이-뭔지-왜-이렇게-만들었는지)
2. [시작하기](#2-시작하기)
3. [5분 만에 첫 트레이싱](#3-5분-만에-첫-트레이싱)
4. [먼저 알아야 할 eBPF 개념](#4-먼저-알아야-할-ebpf-개념)
5. [코드 구조와 개발 사이클](#5-코드-구조와-개발-사이클)
6. [예제 7개 상세](#6-예제-7개-상세)

**게임 트랙 (직접 채우는 챌린지)**

7. [🎮 보안 게임 트랙 (08~14)](#7--보안-게임-트랙-0814--직접-채우는-챌린지)

**참고**

8. [디버깅하는 법](#8-디버깅하는-법)
9. [실무에서 걸리는 함정들](#9-실무에서-걸리는-함정들)
10. [Cilium 실습](#10-cilium-실습)
11. [학습 로드맵 5주](#11-학습-로드맵-5주)
12. [명령어 레퍼런스](#12-명령어-레퍼런스)
13. [트러블슈팅](#13-트러블슈팅)
14. [더 읽을 것](#14-더-읽을-것)

---

## 1. 이 랩이 뭔지, 왜 이렇게 만들었는지

### eBPF를 공부할 때 제일 큰 장벽

eBPF는 **리눅스 커널 기능**이다. macOS에는 없다. 보통은 이래서 막힌다:

- VM(UTM, Lima, Multipass)을 띄운다 → 세팅이 오래 걸리고 무겁다
- 클라우드 인스턴스를 빌린다 → 돈이 들고 매번 접속해야 한다
- "커널이 BTF를 지원 안 한다" → CO-RE도 fentry도 못 쓴다

그런데 **Docker Desktop이 이미 리눅스 VM을 돌리고 있고, 그 커널이 필요한 걸 다 갖고 있다.**
확인해보니 이랬다:

| 항목 | 값 | 이게 있어야 되는 일 |
|---|---|---|
| 커널 | 6.10.14-linuxkit aarch64 | TCX(6.6+) 사용 가능 |
| `/sys/kernel/btf/vmlinux` | 존재 (6.2MB) | **CO-RE, fentry/fexit** |
| `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS` | y | **BPF 트램폴린 = fentry 동작** |
| `CONFIG_BPF_LSM` | y | LSM 훅으로 차단까지 (확장 과제) |
| `CONFIG_KPROBES` / `UPROBES` | y | kprobe / uprobe |
| tracefs | 마운트됨 | tracepoint, trace_pipe |

즉 **VM을 따로 만들 필요가 없다.** privileged 컨테이너 하나면 충분하다.
`make check`가 이걸 전부 자동 점검한다 (현재 38/38 통과).

### 왜 Go(cilium/ebpf)인가

eBPF 프로그램은 C로 짜지만, 그걸 **로드하고 붙이고 맵을 읽는 쪽**은 언어를 고를 수 있다.

| | libbpf (C) | **cilium/ebpf (Go)** | BCC (Python) |
|---|---|---|---|
| 배포 | 바이너리 + libbpf | **단일 바이너리** | 대상 서버에 clang 필요 |
| 런타임 컴파일 | 없음 (CO-RE) | 없음 (CO-RE) | 매 실행마다 |
| 실무 사용처 | 커널 도구들 | **Cilium, Tetragon, Falco 일부** | 탐색/디버깅 |

`bpf2go`가 C를 `.o`로 컴파일하고 그 바이트를 Go 소스에 임베드한다. 결과물은
**의존성 없는 단일 바이너리**다. 대상 서버에 clang도 libbpf도 커널 헤더도 필요 없다.
이게 Cilium이 Go를 쓰는 이유이자, 실무에서 eBPF 도구를 배포하는 표준 방식이다.

### 구성

```
ebpf-lab/
├── compose.yaml              lab(실습) + victim(트레이싱 대상) 컨테이너
├── docker/Dockerfile         clang 18 + llvm + bpftool 7.5 + go 1.26 + bpftrace
├── Makefile                  호스트/컨테이너 어디서 실행해도 동작하는 진입점
├── include/vmlinux.h         실행 중인 커널 BTF에서 뽑은 타입 정의 (자동 생성, 15만 줄)
├── scripts/check-env.sh      커널 기능 점검 (38개 항목)
├── target/workload/          uprobe 실습 대상 Go 프로그램
├── examples/
│   ├── 01-kprobe-unlink/         kprobe + ringbuf
│   ├── 02-tracepoint-openat/     tracepoint + 해시맵 집계
│   ├── 03-fentry-tcpconnect/     fentry/fexit + CO-RE
│   ├── 04-uprobe-go/             uprobe (유저 공간, Go regabi)
│   ├── 05-xdp-count/             XDP  (+ solution/ : 실습형)
│   ├── 06-tcx-egress/            TCX (현대 Cilium 데이터패스)
│   ├── 07-runtime-audit/         실무형 에이전트 (멀티 프로브 + 컨테이너 귀속 + 메트릭)
│   │
│   │   # ↓ 게임 트랙 (각 폴더에 main.go 심판 + check.sh 채점 + solution/ 정답)
│   ├── 08-tc-mangle/             패킷 변조 (TTL/DNAT) — Red 무기
│   ├── 09-tamper-detect/         변조 vs 탐지 (IDS 원리)
│   ├── 10-lsm-guard/             LSM 실행 차단
│   ├── 11-xdp-ddos/              XDP DDoS(SYN flood) 방어
│   ├── 12-anticheat/             uprobe 안티치트
│   ├── 13-mini-av/               미니 백신 (시그니처 격리)
│   └── 14-ids-ips/               IDS/IPS (페이로드 시그니처)
├── target/
│   ├── workload/                 04 uprobe 타깃
│   └── game/                     12 안티치트 타깃
└── cilium/                   kind + Cilium 클러스터 실습
    ├── setup.sh / teardown.sh
    ├── kind-config.yaml
    ├── manifests/starwars.yaml
    ├── policies/             L3L4 / L7 HTTP / DNS egress
    └── exercises.md          ★ Cilium 실습 과제 (여기에 상세히 있음)
```

### 컨테이너에 왜 이런 권한을 줬나

`compose.yaml`의 설정은 전부 이유가 있다. 나중에 실무에서 DaemonSet으로 배포할 때
똑같은 걸 챙겨야 하므로 알아두면 좋다.

| 설정 | 없으면 생기는 일 |
|---|---|
| `privileged: true` | BPF 프로그램 로드 자체가 안 된다 (최소 권한은 `CAP_BPF`+`CAP_PERFMON`+`CAP_NET_ADMIN`) |
| `pid: host` | 다른 컨테이너/호스트 프로세스가 안 보인다. PID가 컨테이너 내부 번호로 나온다 |
| `cgroup: host` | `/sys/fs/cgroup`에 자기 것만 보여서 **컨테이너 귀속(07번)이 불가능** |
| `/sys/kernel/debug` 마운트 | kprobe/uprobe 부착 실패 (tracefs 필요) |
| `/sys/fs/bpf` 마운트 | 맵 pinning 불가 |
| `/var/run/docker.sock` (ro) | 컨테이너 *이름*을 못 가져온다 (ID만 표시) |
| `ulimits.memlock: -1` | 구 커널에서 맵 생성 실패 (5.11+는 memcg라 무관) |

---

## 2. 시작하기

### 이미 세팅되어 있다

컨테이너와 클러스터가 **지금 실행 중**이다. 확인만 하면 된다:

```bash
cd ebpf-lab
docker compose ps        # ebpf-lab, ebpf-victim 이 Up 이어야 한다
make check               # "통과 38 / 실패 0" 이어야 한다
make list                # 예제 목록
```

### 처음부터 다시 만들 때 (또는 다른 맥에서)

```bash
cd ebpf-lab
make image      # 이미지 빌드 (clang/llvm/bpftool 소스 빌드/go) — 약 3분
make setup      # 컨테이너 기동 + vmlinux.h 생성 + Go 의존성 + bpf2go 코드 생성
make check      # 환경 점검
```

### 매일 시작할 때

```bash
cd ebpf-lab
make up         # 컨테이너 기동 (이미 떠 있으면 아무 일도 안 일어난다)
make 01         # 바로 실습
```

### `make`는 어디서 실행해도 된다

이 Makefile은 `/​.dockerenv` 존재 여부로 자기가 어디 있는지 판단한다.

- **macOS 터미널에서** `make 01` → 자동으로 `docker compose exec lab go run ...`으로 감싼다
- **컨테이너 안에서** `make 01` → 그대로 실행

그래서 맥에서 편집하고 맥에서 `make`만 치면 된다. 컨테이너 안으로 들어가고 싶으면 `make sh`.

### 터미널 2개로 쓰는 게 편하다

대부분의 예제는 "트레이서를 띄워놓고 이벤트를 발생시키는" 구조다.

```bash
# 터미널 A - 트레이서
make 01

# 터미널 B - 이벤트 발생
make noise                    # 파일 삭제 + open + ping + TCP 접속을 한 번에
# 또는 직접
make sh
  touch /tmp/x && rm /tmp/x
```

---

## 3. 5분 만에 첫 트레이싱

개념 설명 전에 일단 돌려보는 게 빠르다.

```bash
# 터미널 A
make 01
```

```
kprobe/do_unlinkat 부착 완료. Ctrl-C 로 종료.

PID      TID      COMM             FILENAME
```

```bash
# 터미널 B
make sh
  touch /tmp/hello && rm /tmp/hello
```

터미널 A에 이렇게 찍힌다:

```
56743    56743    rm               /tmp/hello
36652    36655    containerd-shim  /tmp/runc-process1523686498
319      85351    dockerd          /var/run/docker/containerd/0a40e61c.../0fc
```

**여기서 이미 3가지를 배웠다:**

1. 커널 함수 `do_unlinkat()`에 프로그램을 심어서 **모든 파일 삭제를 가로챘다**
2. `pid: host` 덕분에 내 컨테이너뿐 아니라 **호스트 VM의 dockerd, containerd까지 다 보인다**.
   커널은 하나뿐이고, 컨테이너는 그냥 격리된 프로세스일 뿐이라는 게 눈으로 보인다
3. 이건 `rm`을 감시한 게 아니다. **어떤 프로그램이든** `unlink(2)`를 부르면 걸린다.
   우회할 방법이 없다 — 이게 eBPF 기반 보안 도구가 강력한 이유다

이제 무슨 일이 벌어진 건지 이해할 차례다.

---

## 4. 먼저 알아야 할 eBPF 개념

코드를 읽기 전에 이 4가지만 잡고 가면 나머지는 따라온다.

### 4.1 eBPF가 하는 일 — 한 문장

> **커널을 다시 컴파일하거나 모듈을 올리지 않고, 커널 안에서 내 코드를 안전하게 실행한다.**

전통적으로 커널 동작을 바꾸려면 커널 모듈을 짜야 했다. 모듈은 버그 하나로
시스템 전체를 죽인다. eBPF는 **verifier**라는 검증기를 통과한 코드만 실행하므로
커널을 죽일 수 없다. 대신 제약이 많다 (무한 루프 금지, 스택 512바이트, 등).

실행 흐름:

```
 .bpf.c  --clang-->  BPF 바이트코드(.o)  --bpf(2)-->  [verifier 검증]  -->  JIT  -->  커널에서 실행
                                                            |
                                                       실패하면 로드 거부
                                                       (에러 로그가 매우 길다)
```

프로그램은 혼자 못 산다. **훅 포인트에 붙어야(attach)** 실행되고,
**맵(map)으로 유저 공간과 대화한다.**

```
  [유저 공간 Go 프로그램]                    [커널]
        |                                       |
        | 1. 로드 (bpf 시스템콜)                 |
        |-------------------------------------->| verifier 통과 -> JIT
        | 2. 훅에 부착 (attach)                  |
        |-------------------------------------->| do_unlinkat() 진입 시 실행됨
        |                                       |
        | 3. 맵으로 데이터 주고받기               |
        |<-------------- ringbuf ---------------| 이벤트 스트리밍
        |--------------- hash ----------------->| 설정 주입
```

### 4.2 훅 포인트 — 어디에 붙일 것인가

**이 선택이 eBPF 개발의 8할이다.** 잘못 고르면 커널 버전 바뀔 때마다 깨진다.

| 훅 | 붙는 곳 | 안정성 | 언제 쓰나 | 예제 |
|---|---|---|---|---|
| **kprobe** | 아무 커널 함수 진입점 | ⚠️ 낮음 | tracepoint가 없는 내부 함수 | 01 |
| kretprobe | 커널 함수 반환 | ⚠️ 낮음 | 반환값이 필요할 때 (fexit 권장) | - |
| **tracepoint** | 커널이 공식 선언한 지점 | ✅ 높음 (ABI) | 시스템콜, 스케줄러 이벤트 | 02, 07 |
| **fentry/fexit** | 함수 진입/반환 (BTF 기반) | ✅ 높음 | **커널 5.5+면 kprobe 대신 이걸** | 03, 07 |
| **uprobe** | 유저 공간 바이너리 오프셋 | ⚠️ 낮음 | 앱 내부 함수 추적 | 04 |
| **XDP** | 드라이버 수신 직후 | ✅ | 최고속 패킷 처리, DDoS 드롭 | 05 |
| **TC/TCX** | 네트워크 스택 (skb 있음) | ✅ | 양방향, 메타데이터 풍부 | 06 |
| LSM | 보안 훅 | ✅ | **차단**까지 (관찰만이 아니라) | 확장 과제 |

**선택 기준 (실무 순서):**

```
1) tracepoint가 있나?         -> 있으면 무조건 tracepoint (가장 안 깨진다)
   ls /sys/kernel/debug/tracing/events/

2) 없으면, BTF에 그 함수가 있나?  -> 있으면 fentry (타입 안전 + 빠름)
   bpftrace -l 'kfunc:*tcp_connect*'

3) 그것도 없으면 kprobe        -> 커널 버전마다 깨질 각오
   grep ' t 함수명$' /proc/kallsyms
```

**왜 kprobe가 위험한가:** `do_unlinkat(int dfd, struct filename *name)`의 인자 순서나
타입이 커널 버전에서 바뀌면, 컴파일은 되지만 **엉뚱한 메모리를 읽는다.**
fentry는 BTF로 시그니처를 알기 때문에 틀리면 **로드 시점에 verifier가 거부**한다.

**시스템콜에 kprobe를 붙이면 안 되는 이유:** 실제 심볼 이름이 아키텍처마다 다르다.
arm64는 `__arm64_sys_openat`, x86_64는 `__x64_sys_openat`. tracepoint를 쓰면 이 문제가 사라진다.

### 4.3 맵 — 커널과 유저 공간의 유일한 통로

BPF 프로그램은 `printf`를 못 쓴다 (디버깅용 `bpf_printk`는 있지만 느리다).
데이터를 밖으로 빼려면 **맵**을 쓴다.

| 맵 타입 | 용도 | 이 랩에서 |
|---|---|---|
| **RINGBUF** | 이벤트 스트리밍 (커널→유저, 순서 보장, 5.8+) | 01, 03, 04, 07 |
| PERF_EVENT_ARRAY | ringbuf 이전 세대. CPU별 버퍼라 순서 안 맞음 | - |
| **HASH** | 키-값 집계 | 02 |
| **PERCPU_ARRAY** | CPU별 카운터 (경쟁 없음, 읽을 때 합산) | 02, 03, 05, 06, 07 |
| ARRAY | 고정 인덱스 설정/통계 | 07 (config) |
| LRU_HASH | 오래된 항목 자동 축출 (캐시) | 확장 과제 |
| LPM_TRIE | CIDR 매칭 (IP 정책) | Cilium이 사용 |

**핵심 설계 판단 — 스트리밍 vs 집계:**

```
이벤트 빈도가 낮다 (파일 삭제, TCP 커넥트)
  -> RINGBUF로 하나하나 올린다. 상세 정보를 다 볼 수 있다.        [01, 03]

이벤트 빈도가 높다 (openat, 패킷 수신)
  -> 커널 안에서 맵에 누적하고 유저는 1초에 한 번 읽는다.          [02, 05, 06]
     초당 수만 건을 전부 유저 공간에 올리면 그게 곧 성능 문제다.
```

07번은 둘 다 쓴다 — 이벤트는 ringbuf, 통계는 PERCPU_ARRAY.

**PERCPU 맵을 읽을 때 주의:** 유저 공간에서는 값 하나가 아니라 **CPU 개수만큼의
배열**로 돌아온다. 직접 합산해야 한다.

```go
var perCPU []uint64
objs.Total.Lookup(uint32(0), &perCPU)
var sum uint64
for _, v := range perCPU { sum += v }
```

### 4.4 verifier가 요구하는 것 / CO-RE가 푸는 문제

**verifier 규칙** (어기면 로드 거부):

- 무한 루프 금지 (유한 루프는 5.3+에서 제한적 허용)
- 스택 512바이트 — 큰 구조체는 맵에 넣어서 쓴다
- **모든 포인터 역참조 전에 NULL 검사**
- 패킷 데이터는 **`data`/`data_end` 경계 검사 후에만** 접근 (05번 XDP 예제 참고)
- 명령어 수 제한 (100만, 구버전은 4096)

```c
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)   /* 이 줄이 없으면 로드 거부 */
    return XDP_PASS;
```

이 강제성이 "커널에서 임의 코드를 돌려도 안전한" 근거다.

**CO-RE (Compile Once, Run Everywhere)가 푸는 문제:**

커널 구조체 필드의 오프셋은 **커널 빌드마다 다르다.** `struct sock`의
`skc_daddr`이 이 커널에서는 +40이지만 저 커널에서는 +48일 수 있다.
옛날에는 대상 서버에서 커널 헤더를 받아 그때그때 컴파일했다 (BCC 방식).

CO-RE는 이렇게 푼다:

```
1. 커널이 자기 타입 정보를 BTF로 노출한다     /sys/kernel/btf/vmlinux
2. bpftool로 그걸 C 헤더로 뽑는다             make vmlinux -> include/vmlinux.h
3. BPF_CORE_READ()로 필드를 읽으면 컴파일러가 "재배치 정보"를 남긴다
4. 로드할 때 libbpf/cilium-ebpf가 현재 커널 BTF를 보고 오프셋을 고쳐 넣는다
```

그래서 코드에서 이렇게 쓴다:

```c
/* 나쁨: 오프셋 하드코딩과 다름없다 */
__u32 daddr = sk->__sk_common.skc_daddr;

/* 좋음: CO-RE 재배치가 걸린다 */
__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
```

---

## 5. 코드 구조와 개발 사이클

### 파일은 항상 한 쌍이다

```
examples/01-kprobe-unlink/
├── unlink.bpf.c              커널에서 돌 코드 (C)
├── main.go                   유저 공간 코드 (Go) — 로드/부착/맵 읽기
├── unlink_arm64_bpfel.go     ← bpf2go가 생성 (건드리지 말 것)
└── unlink_arm64_bpfel.o      ← bpf2go가 생성 (컴파일된 BPF 바이트코드)
```

`main.go` 맨 위의 이 한 줄이 생성을 지시한다:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type event unlink unlink.bpf.c -- -I../../include -Wall
//                                                       ↑             ↑          ↑      ↑                  ↑
//                                            아키텍처(arm64)   Go 구조체로   접두사  소스   vmlinux.h 위치
//                                                            뽑을 C 타입
```

생성된 파일이 주는 것:

| 생성물 | 정체 |
|---|---|
| `unlinkObjects` | 맵과 프로그램을 담는 구조체 |
| `loadUnlinkObjects()` | `.o`를 커널에 로드하는 함수 |
| `unlinkEvent` | C의 `struct event`에 대응하는 Go 구조체 (BTF에서 자동 생성) |
| `objs.DoUnlinkat` | C의 `SEC("kprobe/do_unlinkat")` 프로그램 |
| `objs.Events` | C의 `events` 맵 |

**C 이름 → Go 이름 변환 규칙:** snake_case → CamelCase.
`config_map` → `ConfigMap`, `trace_tcp_connect` → `TraceTcpConnect`.

### Go 쪽 코드의 뼈대 (전부 똑같다)

```go
rlimit.RemoveMemlock()                    // 1. 구 커널용 제한 해제

var objs unlinkObjects
loadUnlinkObjects(&objs, nil)             // 2. 커널에 로드 (verifier 검증이 여기서)
defer objs.Close()

l, _ := link.Kprobe("do_unlinkat", objs.DoUnlinkat, nil)   // 3. 훅에 부착
defer l.Close()

rd, _ := ringbuf.NewReader(objs.Events)   // 4. 맵 읽기
for {
    rec, _ := rd.Read()
    binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev)
    fmt.Println(ev)
}
```

부착 함수는 훅 종류마다 다르다:

```go
link.Kprobe("do_unlinkat", prog, nil)                              // kprobe
link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)         // tracepoint
link.AttachTracing(link.TracingOptions{Program: prog})             // fentry/fexit
ex, _ := link.OpenExecutable(path); ex.Uprobe("main.compute", prog, nil)  // uprobe
link.AttachXDP(link.XDPOptions{Program: prog, Interface: idx, Flags: link.XDPGenericMode})
link.AttachTCX(link.TCXOptions{Program: prog, Interface: idx, Attach: ebpf.AttachTCXIngress})
```

**fentry에는 심볼 이름을 안 넘긴다.** 대상 함수가 이미 프로그램의 BTF에 박혀 있기 때문이다
(`SEC("fentry/tcp_connect")`). 이것만 봐도 fentry가 왜 더 안전한지 알 수 있다.

### 수정 → 실행 사이클

```bash
# 1. .bpf.c 나 main.go 를 맥에서 편집 (VS Code 등)
vim examples/01-kprobe-unlink/unlink.bpf.c

# 2. 그냥 실행하면 된다. Makefile이 .bpf.c 변경을 감지해서 자동 재생성한다
make 01

# 수동으로 하려면
make generate      # bpf2go 재실행 (.bpf.c -> .o + Go 바인딩)
make build         # 전부 bin/ 으로 빌드
make vet           # go vet
```

`make generate`는 `include/vmlinux.h`가 있어야 동작한다. 없으면 `make vmlinux`가 먼저 돈다.

### 새 예제를 만들려면

```bash
mkdir examples/08-my-tracer
cd examples/08-my-tracer
# 1. mytracer.bpf.c 작성 (기존 예제 복사해서 시작하는 게 빠르다)
# 2. main.go 작성 + go:generate 줄 추가
# 3. make generate && go run ./examples/08-my-tracer
```

`Makefile`의 `01`~`07` 타깃을 흉내내면 `make 08`도 만들 수 있다.

---

## 6. 예제 7개 상세

각 예제마다 **직접 해볼 것**을 달아뒀다. 읽기만 하면 안 남는다. 고쳐봐야 한다.

### 과제 난이도 사다리

과제는 전부 4단계로 매겨져 있다. **Lv1부터 순서대로** 올라가는 게 중요하다.
건너뛰면 "내 로직이 틀린 건지 verifier가 이 패턴을 싫어하는 건지" 구분이 안 돼서 막힌다.

| | 난이도 | 무엇을 하나 | 새로 배우는 것 |
|---|---|---|---|
| **Lv1** | 쉬움 | 필드 하나 추가, 출력 바꾸기 | **수정 → 재생성 → 실행** 사이클을 손에 익힌다 |
| **Lv2** | 보통 | 상수·자료구조 바꾸기 | BPF의 제약(스택 512B 등)을 몸으로 만난다 |
| **Lv3** | 어려움 | 커널에서 조건 분기·필터링 | verifier와 처음 싸운다 |
| **Lv4** | 도전 | 후킹 대상을 다른 함수로 교체 | 시그니처를 직접 알아내야 한다 |

**Lv1은 30분, Lv4는 반나절**을 잡으면 된다. Lv4가 안 풀려도 정상이다 —
막히면 그 상태로 질문하는 게 혼자 3시간 헤매는 것보다 훨씬 낫다.

**모든 Lv1의 공통 사이클** (이걸 먼저 손에 익히는 게 목적):

```bash
# 1. .bpf.c 의 struct event 에 필드 추가
# 2. Go 쪽 출력에 그 필드 추가
make 01          # .bpf.c 변경을 감지해 bpf2go가 자동 재생성된다
```

C 구조체를 고치면 Go 구조체(`unlinkEvent`)도 **자동으로 따라 바뀐다.**
BTF에서 생성하기 때문이다. 이 사실을 Lv1에서 체감해두면 나머지가 쉬워진다.

### 01. kprobe — 커널 함수 진입점 후킹

```bash
make 01
# 터미널 B: make sh -> touch /tmp/x && rm /tmp/x
```

`do_unlinkat()`(unlink 시스템콜의 실제 구현부)에 브레이크포인트를 심고,
`struct filename`에서 경로 문자열을 읽어 ringbuf로 올린다.

- 배우는 것: 로드 → 부착 → ringbuf 스트리밍의 전체 흐름
- `BPF_KPROBE()` 매크로가 `pt_regs`에서 인자를 꺼내주는 것
- `bpf_probe_read_kernel_str()`로 커널 포인터를 안전하게 읽는 것

> **직접 해볼 것**
>
> **Lv1 — 이벤트에 UID 추가** *(첫 수정 과제. 사이클 익히기가 목적)*
> `struct event`에 `__u32 uid;`를 넣고 `bpf_get_current_uid_gid()`로 채운 뒤
> Go 출력에 컬럼을 하나 늘린다.
> `bpf_get_current_uid_gid()`는 상위 32비트가 GID, 하위가 UID다.
> → 확인 포인트: C 구조체만 고쳤는데 Go의 `unlinkEvent`도 따라 바뀐다.
>
> **Lv2 — 파일명 버퍼 늘리기**
> `FNAME_LEN`을 96에서 256으로 바꿔보라. 잘 된다. 그럼 4096은?
> → 생각할 것: 왜 무한정 늘릴 수 없나? (BPF 스택은 512바이트다.
>   `struct event`는 어디에 있길래 96바이트 배열이 들어갔을까?)
>
> **Lv3 — 커널에서 필터링**
> `comm`이 `"rm"`인 이벤트만 ringbuf에 올려라.
> `strcmp`는 못 쓴다. 바이트를 직접 비교해야 한다:
> ```c
> if (!(e->comm[0] == 'r' && e->comm[1] == 'm' && e->comm[2] == '\0'))
>     return 0;   /* reserve 했으면 discard 해야 한다 -- 어떤 헬퍼일까? */
> ```
> → 함정: `bpf_ringbuf_reserve()` 후에 그냥 `return` 하면 버퍼가 샌다.
>
> **Lv4 — 후킹 대상 교체**
> `do_unlinkat` 대신 `vfs_write`를 후킹하라. 시그니처가 다르다:
> `BPF_KPROBE(vfs_write, struct file *file, const char *buf, size_t count)`
> → 힌트: 너무 많이 잡히니 `count > 1024`인 것만. 파일 경로는
>   `BPF_CORE_READ(file, f_path.dentry, d_name.name)`으로 꺼낸다.
> → 먼저 확인: `docker compose exec lab grep ' [tT] vfs_write$' /proc/kallsyms`

### 02. tracepoint — 안정적인 후킹 + 커널 내 집계

```bash
make 02
```

`sys_enter_openat` tracepoint로 프로세스별 `openat(2)` 호출 횟수를 해시맵에 누적하고,
유저 공간이 1초마다 읽어서 순위를 출력한다.

- tracepoint는 커널이 ABI로 유지 → 버전이 바뀌어도 안 깨진다
- **스트리밍 대신 집계**: 초당 수천 건 이벤트를 유저 공간에 안 올린다
- `__sync_fetch_and_add`(원자적 증가) vs PERCPU 맵(경쟁 회피) 두 방식이 한 파일에 다 있다

```bash
# 어떤 tracepoint가 있는지 목록 보기
make sh
  ls /sys/kernel/debug/tracing/events/syscalls/ | head -40
  cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
```

`format` 파일이 인자 레이아웃을 알려준다. `args[0]`이 파일명 포인터인 것도 여기서 확인한다.

> **직접 해볼 것**
>
> **Lv1 — 출력만 바꾸기** *(BPF 코드는 안 건드린다)*
> 상위 10개 → 20개로, 정렬을 카운트순 → PID순으로. `main.go`의 `snapshot()`만 고치면 된다.
> → 확인 포인트: 커널 코드를 안 건드려도 되는 변경이 있다. 어디까지가 유저 공간 몫인가?
>
> **Lv2 — 키에 UID 추가**
> `struct proc_key`에 `__u32 uid`를 넣어라. 01번 Lv1과 같은 사이클인데
> 이번엔 **맵의 키**가 바뀐다.
> → 생각할 것: 키가 커지면 맵 메모리가 어떻게 되나? `max_entries 8192`는 충분한가?
>
> **Lv3 — 실패한 openat만 세기**
> `sys_exit_openat` tracepoint를 추가해 반환값이 음수인 것만 별도 카운터에 넣어라.
> → 힌트: `struct trace_event_raw_sys_exit`의 `ret` 필드.
>   진입과 종료를 짝지으려면 PID를 키로 하는 맵이 필요할까, 아닐까?
>
> **Lv4 — 다른 시스템콜로 교체**
> `sys_enter_connect`를 집계하라. `args[1]`이 `struct sockaddr *`인데
> **유저 공간 포인터**다. `bpf_probe_read_user()`를 써야 한다.
> → 먼저 확인: `cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format`

### 03. fentry/fexit — BTF 기반 트레이싱 (Cilium/Tetragon 방식)

```bash
make 03
# victim 컨테이너가 3초마다 HTTP 요청을 보내므로 가만히 둬도 이벤트가 찍힌다
```

`tcp_connect(struct sock *sk)`를 후킹해 소켓에서 주소/포트를 읽는다.
**이 예제가 가장 중요하다.** 현대 eBPF 도구가 실제로 쓰는 방식이다.

kprobe 대비 장점:

| | kprobe | fentry |
|---|---|---|
| 방식 | 브레이크포인트(int3/BRK) | **BPF 트램폴린 직접 호출** |
| 속도 | 느림 | **빠름** |
| 인자 | `pt_regs`에서 수동으로 꺼냄 | **타입 그대로 받음** |
| 시그니처 오류 | 런타임에 엉뚱한 값 | **로드 시점 거부** |
| 반환값 | kretprobe 따로 + 맵에 저장 | **fexit이 인자+반환값 동시에** |

```c
SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect_entry, struct sock *sk) { ... }

SEC("fexit/tcp_connect")
int BPF_PROG(tcp_connect_exit, struct sock *sk, int ret) { ... }
//                             ↑ 진입 인자와 반환값을 한 번에
```

> **직접 해볼 것**
>
> **Lv1 — 소켓 상태 추가**
> 이벤트에 `skc_state`(TCP 상태)를 추가하라.
> `BPF_CORE_READ(sk, __sk_common.skc_state)` 한 줄이다.
> → 확인 포인트: `vmlinux.h`에서 `struct sock_common`을 찾아 어떤 필드가 더 있는지 훑어보라.
>   `grep -n 'struct sock_common {' -A 40 include/vmlinux.h`
>
> **Lv2 — verifier에게 일부러 혼나기** *(이건 꼭 해볼 것)*
> `BPF_PROG(tcp_connect_entry, struct sock *sk, int bogus)` 처럼
> 인자를 하나 더 붙여서 로드해보라.
> → 이게 fentry의 존재 이유다. kprobe였다면 **조용히 쓰레기 값**을 읽었을 텐데
>   fentry는 로드 자체를 거부한다. 에러 메시지를 꼭 읽어볼 것.
>
> **Lv3 — 포트 필터링**
> 목적지 포트가 443인 커넥션만 올려라. 그다음 이 포트 번호를
> **하드코딩하지 말고** 맵으로 빼서 유저 공간에서 주입해보라 (07번이 쓰는 방식).
> → 생각할 것: 왜 재컴파일 없이 바꿀 수 있어야 하나?
>
> **Lv4 — 커넥션 수명 측정**
> `tcp_connect` 진입 시각을 해시맵(키=`sk` 포인터)에 저장하고,
> `tcp_close`에 fexit을 붙여 시각 차이를 계산하라.
> → 먼저 확인: `bpftrace -l 'kfunc:tcp_close'`
> → 함정: 맵에 넣고 지우지 않으면 샌다. 언제 지워야 하나?

### 04. uprobe — 유저 공간 함수 트레이싱

```bash
make 04       # 타깃 프로그램을 자동으로 띄워준다
```

`target/workload`의 `main.compute(n int)` 진입점을 잡아 인자 `n`을 읽는다.

- Go 1.17+는 **레지스터 호출 규약(regabi)**. 첫 정수 인자가 arm64에서 X0, amd64에서 RAX.
  `PT_REGS_PARM1` 매크로가 아키텍처별로 알아서 고른다
- **uretprobe는 Go에 쓰지 말 것.** 고루틴 스택이 이동하면 uretprobe가 심은 복귀 주소가
  무효화되어 대상 프로세스가 죽을 수 있다
- `-ldflags "-s -w"`로 스트립하면 심볼이 없어서 못 붙는다

> **직접 해볼 것**
>
> **Lv1 — 내 함수 추가하고 붙이기**
> `target/workload/main.go`에 `//go:noinline func double(n int) int`를 추가하고
> `make 04 ARGS="-sym main.double"`로 붙여보라. BPF 코드는 안 고쳐도 된다.
> → 확인 포인트: `//go:noinline`을 빼면 어떻게 되나? 왜 그럴까?
>
> **Lv2 — 인자 2개 읽기**
> 인자 2개짜리 함수를 만들고 `PT_REGS_PARM2`로 둘째 인자도 읽어라.
> → 확인 포인트: arm64는 X0, X1. amd64는 RAX, RBX. 매크로가 대신 골라준다.
>
> **Lv3 — 시스템 바이너리에 붙이기** *(동작 확인됨)*
> `make 04 ARGS="-bin /usr/bin/bash -sym readline"`
> ARG가 거대한 숫자로 나온다. `readline(const char *prompt)`의 첫 인자가
> 정수가 아니라 **포인터**이기 때문이다.
> `bpf_probe_read_user_str()`로 문자열을 읽어 프롬프트를 출력해보라.
> → 왜 `bpf_probe_read_kernel_str`이 아니라 `_user_` 인가?
>
> **Lv4 — Go 문자열 읽기**
> Go의 `string`은 `{ptr, len}` 구조체라 **두 레지스터에 나뉘어** 들어온다
> (arm64: X0=ptr, X1=len). NUL로 끝나지 않으므로 `_str` 계열 헬퍼가 아니라
> 길이를 직접 넘기는 `bpf_probe_read_user()`를 써야 한다.
> → 함정: verifier는 "읽을 길이"가 상수이거나 상한이 증명되길 원한다.

### 05. XDP — 네트워크 스택 최전선

```bash
make 05
# 터미널 B: make sh -> ping -c3 1.1.1.1
```

드라이버가 패킷을 받은 직후, `skb`가 만들어지기도 전에 실행된다.
Cilium의 DDoS 드롭과 로드밸런싱이 여기서 일어난다.

- **경계 검사가 강제된다.** `data`/`data_end` 검사 없이 접근하면 verifier가 거부
- veth에는 native XDP가 없으므로 generic(SKB) 모드로 붙인다 (`-native`로 비교 가능)
- 반환값이 패킷의 운명을 결정: `XDP_PASS` / `XDP_DROP` / `XDP_TX` / `XDP_REDIRECT`

> **직접 해볼 것**
>
> **Lv1 — 통계 항목 추가**
> `struct proto_stat`에 `max_len`을 추가해 프로토콜별 최대 패킷 크기를 기록하라.
> → 확인 포인트: PERCPU 맵이라 CPU별로 최댓값이 따로 잡힌다.
>   유저 공간에서 합치면 안 되고 `max`를 취해야 한다. 왜?
>
> **Lv2 — 출발지 IP 기록**
> IP 헤더에서 `saddr`를 읽어 마지막으로 본 출발지를 기록하라.
> → 확인 포인트: `ip->saddr` 접근 전에 이미 경계 검사가 되어 있나? 확인하고 쓸 것.
>
> **Lv3 — 실제로 패킷을 막아보기** *(eBPF의 힘을 처음 체감하는 지점)*
> ICMP만 `XDP_DROP`으로 바꾸고 `ping`이 안 되는 걸 확인하라.
> → 안심하고 해도 된다. Ctrl-C로 프로그램을 끄면 링크가 해제되어 원상복구된다.
> → 생각할 것: 방화벽 규칙 없이 커널에서 패킷이 사라졌다. 어느 계층에서 사라진 건가?
>
> **Lv4 — 가변 길이 IP 헤더 파싱** *(2주차 최고 난이도)*
> TCP 헤더까지 파싱해 포트별로 세어라. IP 헤더 길이가 가변(`ip->ihl * 4`)이라
> verifier가 오프셋을 못 믿는다. 이게 진짜 연습이다.
> → 힌트: `if (ip->ihl < 5 || ip->ihl > 15) return XDP_PASS;` 로 **범위를 증명**해줘야 한다.
> → verifier 에러가 나오면 8.1절 표에서 `math between pkt pointer` 항목을 볼 것.

### 06. TCX — 현대 Cilium 데이터패스 진입점

```bash
make 06
```

커널 6.6+의 TCX로 ingress/egress 양방향에 프로그램을 붙인다.
예전에는 `clsact` qdisc를 netlink로 만들어야 했는데, TCX는 `bpf_link` 하나로 끝난다.

| | XDP | TC/TCX |
|---|---|---|
| 실행 시점 | skb 생성 전 | skb 있음 |
| 방향 | ingress만 | **ingress + egress** |
| 속도 | 가장 빠름 | 약간 느림 |
| 메타데이터 | 제한적 | 풍부 (`__sk_buff`) |
| 정리 | 명시적 detach 필요 | **프로세스 죽으면 자동 해제** |

> **직접 해볼 것**
>
> **Lv1 — 평균 패킷 크기**
> 방향별 평균 크기를 출력하라. `bytes / packets`이므로 Go에서 계산하면 된다.
>
> **Lv2 — 포트별 집계**
> `bpf_skb_load_bytes`로 TCP 헤더까지 읽어 목적지 포트별로 세어라.
> XDP(05번 Lv4)와 달리 여기서는 **경계 검사 대신 헬퍼가 대신 검사**해준다.
> → 비교해볼 것: 왜 TC에서는 이 헬퍼를 쓰는 게 더 편한가?
>
> **Lv3 — egress에서 막아보기**
> 특정 목적지 포트로 나가는 패킷을 `TC_ACT_SHOT`으로 드롭하라.
> → XDP는 ingress만 되지만 TC는 **나가는 것도 막을 수 있다.** 이 차이가 중요하다.
>
> **Lv4 — Cilium과 비교**
> `make cilium-bpf`로 `cil_from_container`, `cil_to_container` 같은 프로그램을 찾아라.
> Cilium 소스의 `bpf/bpf_lxc.c`를 열어 우리가 짠 것과 **같은 문법**인지 확인하라.

### 07. 실무형 런타임 감시 에이전트 ★

```bash
make 07
make 07 ARGS="-json"                        # 구조화 로그 (JSON Lines)
make 07 ARGS="-metrics :9101"               # curl localhost:9101/metrics
make 07 ARGS="-container ebpf-victim"       # 특정 컨테이너만 (커널에서 필터링)
make 07 ARGS="-pin"                         # bpftool로 맵을 들여다볼 수 있게 pin
```

01~06이 "기능 하나"였다면 이건 **제품 구조**다. Tetragon/Falco의 축소판.

```
TIME         KIND     CONTAINER          PID    PPID   UID  COMM      DETAIL
16:47:56.643 EXEC     ebpf-victim        60327  52902  0    sh        /usr/bin/wget
16:47:56.650 CONNECT  ebpf-victim        60327  52902  0    wget      104.20.23.154:80
16:47:57.217 UNLINK   ebpf-lab           60330  60287  0    rm        /tmp/aa
16:47:57.650 CONNECT  lt-log-aggregator  89051  89027  0    main      172.19.0.6:4000
```

실무에서 반드시 필요해지는 7가지가 전부 들어있다:

1. **프로브 3개를 하나의 오브젝트로** — 프로브마다 맵/링버퍼를 따로 만들면 관리비용이 폭발.
   이벤트 종류(`kind`) 필드로 구분한다
2. **커널 단계 필터링** — 자기 PID를 안 걸러내면 에이전트가 자기 로그를 보고 또 이벤트를
   만드는 **피드백 루프**가 생긴다. cgroup 필터도 커널에서 한다
3. **런타임 설정 맵** — 재컴파일 없이 프로브를 켜고 끈다. 실제 제품은 여기에 정책이 들어간다
4. **유실 카운터** — 링버퍼가 꽉 차면 이벤트가 조용히 사라진다.
   몇 개 잃었는지 모르는 관측 시스템은 신뢰할 수 없다 → `ebpf_audit_dropped_total`
5. **컨테이너 귀속** — `bpf_get_current_cgroup_id()` 값은 cgroup v2에서
   **cgroup 디렉터리의 inode 번호**다. `/sys/fs/cgroup`을 걸어서 매핑을 만든다.
   컨테이너 *이름*은 커널에 없어서 도커 소켓에 물어본다 (K8s면 CRI/API 서버)
6. **맵 pinning** — `/sys/fs/bpf`에 pin하면 프로세스 밖에서도 상태를 볼 수 있다.
   Cilium이 agent 재시작 중에도 데이터패스를 유지하는 원리
7. **verifier 로그 처리** — 로드 실패 시 `%+v`로 전문을 찍는다

```bash
# 실행 중에 다른 터미널에서 — 이게 pinning의 실용성이다
make 07 ARGS="-pin"       # 터미널 A
docker compose exec lab bpftool map dump pinned /sys/fs/bpf/ebpf-audit/stats
docker compose exec lab bpftool map dump pinned /sys/fs/bpf/ebpf-audit/config
make links                # bpf_link가 어디에 붙어 있는지
```

파일 구성도 실무 형태다:

| 파일 | 역할 |
|---|---|
| `audit.bpf.c` | 커널 측 — 프로브 3개 + 필터 + 통계 |
| `main.go` | 로드/부착/이벤트 루프/출력 |
| `container.go` | cgroup id → 컨테이너 이름 해석 |
| `metrics.go` | Prometheus 텍스트 포맷 (의존성 없이 직접) |

> **직접 해볼 것**
>
> **Lv1 — 통계 항목 하나 추가**
> `stats` 맵에 슬롯을 하나 늘려 "IPv6라서 건너뛴 커넥션 수"를 세고
> `/metrics`에 노출하라. 03번에 이미 있는 코드라 참고하면 된다.
>
> **Lv2 — 유실을 직접 만들어보기** *(관측 시스템의 핵심 감각)*
> ringbuf `max_entries`를 1MB → 4KB로 줄이고 `make noise`로 부하를 걸어
> `dropped_total`이 오르는 걸 확인하라.
> → 생각할 것: 프로덕션에서 이 값이 0이 아니면 무슨 뜻인가?
>   버퍼를 키우는 것과 커널 필터를 좁히는 것 중 뭐가 먼저인가?
>
> **Lv3 — 정확한 프로세스 이름 얻기**
> `sys_enter_execve` 대신 `sched_process_exec` tracepoint로 바꿔라.
> 이 tracepoint는 `__data_loc` 방식이라 파일명 읽는 법이 다르다 — 이게 이번 난관이다.
> → 먼저 확인: `cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/format`
> → 9장 "exec 시점의 comm" 함정 절을 다시 읽고 시작할 것.
>
> **Lv4 — LSM 훅으로 실제 차단** *(관찰에서 제어로 넘어가는 지점)*
> `CONFIG_BPF_LSM=y`라 가능하다. `SEC("lsm/file_open")`에서 특정 경로면
> `-EPERM`을 리턴하면 **진짜로 열리지 않는다.**
> → 확인: `docker compose exec lab bpftool feature probe | grep "lsm is available"`
> → 주의: 잘못 짜면 컨테이너 안에서 아무것도 실행 못 하게 될 수 있다.
>   경로를 좁게 잡고(`/tmp/blocked` 같은) 시작하라. 최악의 경우 `make down && make up`.
>
> **Lv5 — 자기 도구 만들기** *(3주차 마지막)*
> `examples/08-my-tracer/`를 빈 디렉토리에서 시작한다. 아이디어는 11장 참고.

---

## 7. 🎮 보안 게임 트랙 (08~14) — 직접 채우는 챌린지

01~07 이 "동작하는 코드를 읽고 이해하는" 학습 트랙이라면, 08~14 는
**핵심 로직을 네가 직접 채우는 게임 트랙**이다. 관측을 넘어 실제로 **변조하고,
차단하고, 탐지**한다. 전부 loopback 안에서 벌어지는 자가 검증이라 외부 대상이 없다.

### 게임의 구조

각 게임 디렉토리는 이렇게 생겼다:

```
examples/09-tamper-detect/
├── detect.bpf.c          ← 네가 채우는 게임판 (TODO 빈칸)
├── main.go               ← 심판 (실시간 점수판)
├── check.sh              ← 자동 채점 (점수제 스코어카드)
└── solution/detect.bpf.c ← 숨긴 정답 (막히면 참고)
```

**진행 방식:**

```bash
make 09          # 게임 실행 -> 지금은 TODO 가 비어서 아무것도 못 잡는다
# examples/09-tamper-detect/detect.bpf.c 의 TODO 를 채운다
make 09-check    # 자동 채점: 점수가 나온다
```

채점은 **점수제 스코어카드**다. 케이스별로 배점이 있고, 부분 점수로 "어디까지 됐는지"가 보인다:

```
╔═══ 11. XDP DDoS 방어 채점 ═══╗
  ✅ [ 20점] 빌드
  ✅ [ 25점] 정상 트래픽(소량 SYN)은 통과   차단 0
  ✅ [ 20점] SYN 을 검사한다                검사 305
  ⬜ [  0점] flood 미차단                   ddos.bpf.c TODO 확인
──────────────────────────────
  점수: 65/100   (통과 기준 70점)
```

빈칸 상태로도 빌드는 되고 부분 점수(위 예: 65점)가 나온다. TODO 를 채워
70점을 넘으면 클리어다. 막히면 `solution/` 을 열어본다.

### 게임 목록

| # | 게임 | 배우는 것 | 훅 | 네가 채우는 것 |
|---|---|---|---|---|
| **08** | TC 패킷 변조 | 패킷을 실제로 고쳐 내보내기 + 체크섬 | TCX egress | (도구라 완성본 제공) |
| **09** | 변조 vs 탐지 | 무결성 검사(IDS 원리) | TCX ingress | TTL/포트/헤더 불변식 |
| **10** | LSM 실행 차단 | 관찰이 아니라 **차단** | lsm/bprm | 실행 파일명 검사 → -EPERM |
| **11** | XDP DDoS 방어 | 드라이버 최전선에서 flood 차단 | XDP | 출발지별 SYN 레이트 리밋 |
| **12** | 안티치트 | 게임 메모리 조작 탐지 | uprobe | 규칙 위반값(HP>100) 판정 |
| **13** | 미니 백신 | 시그니처 기반 파일 격리 | lsm/file_open | 시그니처 매칭 → 차단 |
| **14** | IDS/IPS | 페이로드 시그니처 탐지·차단 | TCX ingress | 시그니처 + 모드(탐지/차단) |

### 08. TC 패킷 변조 (Red 무기)

```bash
# TTL 을 42 로 바꾸기 (체크섬 자동 재계산 -> ping 은 계속 된다)
make 08 ARGS="-iface lo -action ttl -ttl 42"

# 목적지 포트 8080 -> 9090 DNAT (양방향)
make 08 ARGS="-iface lo -action dnat -match 8080 -to 9090"
#   터미널 B: nc -lk -p 9090       (서버)
#   터미널 C: nc 127.0.0.1 8080    (8080 을 쳤는데 9090 서버에 붙는다!)
```

08 은 09/14 게임에서 "공격자(Red)" 무기로 쓴다. 패킷 변조의 핵심은 **체크섬 증분
재계산**이다. `bpf_skb_store_bytes` 로 값을 쓴 뒤 `bpf_l3/l4_csum_replace` 를 안 하면
커널이 그 패킷을 조용히 버린다. (검증: TTL 을 바꿔도 ping 손실이 0% 여야 정답)

> **직접 해볼 것 (08 은 완성본이지만 확장 가능)**
> - DNAT 가 단방향이면 TCP 가 왜 안 되는지 확인하고, 역방향 되돌림(conntrack 원리)을 지워보라.
> - DSCP 마킹(`-action dscp`)을 추가로 실험.

### 09. 변조 vs 탐지 (Red vs Blue)

```bash
make 09                                          # 🔵 Blue 탐지기(심판)
make 08 ARGS="-iface lo -action ttl -ttl 42"     # 🔴 Red 공격 (다른 터미널)
make sh -> ping -c5 127.0.0.1                     # 트래픽
make 09-check                                     # 채점
```

`detect.bpf.c` 의 TODO 를 채워 "loopback 트래픽의 TTL 은 64 여야 한다" 같은
**불변식**이 깨지는 순간을 잡는다. IDS(침입탐지)의 기본 원리다.

### 10. LSM 실행 차단

```bash
make 10
make sh -> cp /bin/echo /tmp/malware && /tmp/malware   # 채운 뒤: Operation not permitted
make 10-check
```

`lsm/bprm_check_security` 에서 `-EPERM` 을 리턴하면 커널이 실행 자체를 거부한다.
관찰에서 **제어**로 넘어가는 첫 게임. (이 커널은 `CONFIG_LSM` 에 bpf 가 있어 실제로 막힌다)

### 11. XDP DDoS 방어

```bash
make 11 ARGS="-iface lo -rate 50"
make 11-check     # SYN flood 를 쏴서 임계값 초과분이 차단되는지 채점
```

XDP 는 skb 생성 전 최전선이다. 출발지 IP 별 SYN 레이트를 **LRU 해시맵**으로 재고
임계값을 넘으면 `XDP_DROP`. Cloudflare/Cilium 이 대용량 공격을 흡수하는 그 지점.

### 12. 안티치트 (메모리 조작 탐지)

```bash
make game                     # 실습용 게임 타깃 빌드
make 12                       # 안티치트(심판)
make sh -> /opt/lab/bin/game -cheat   # 치트 실행 (HP=9999)
make 12-check
```

게임의 `setHealth()` 에 uprobe 를 붙여 인자가 규칙(HP<=100)을 위반하는 순간을 잡는다.
치트 프로그램을 **고치지 않고, 바이너리에 손대지 않고** 커널에서 탐지한다.

### 13. 미니 백신 (시그니처 격리)

```bash
make 13
make sh -> echo bad > /tmp/x.virus.txt && cat /tmp/x.virus.txt   # 채운 뒤: 격리
make 13-check
```

`lsm/file_open` 에서 파일명 시그니처(`.virus`)를 검사해 열기 자체를 막는다.
진짜 백신의 1차 필터(이름/경로)를 커널에서 구현. 2차(내용 해시)는 확장 과제.

### 14. IDS/IPS (페이로드 시그니처)

```bash
make 14 ARGS="-iface lo -mode ids"    # 탐지만 (경보 + 통과)
make 14 ARGS="-iface lo -mode ips"    # 차단 (경보 + 드롭)
make sh -> echo 'x-EVIL-x' | nc -u -w1 127.0.0.1 9999
make 14-check
```

Snort/Suricata 처럼 UDP 페이로드에서 악성 시그니처("EVIL")를 찾는다.
같은 엔진에 모드 스위치 하나로 IDS(탐지) ↔ IPS(차단). 실무에서 IPS 를 인라인으로
걸면 오탐 하나가 정상 트래픽을 끊으므로, 보통 IDS 로 관찰한 뒤 IPS 로 승격한다.

> **페이로드 스캔의 함정**: verifier 는 `bpf_skb_load_bytes` 의 크기가 0 이 될 수
> 있으면 거부한다("zero-sized read"). 그래서 14 는 각 위치에서 **상수 4바이트씩**
> 읽어 비교한다. 변수 크기 로드는 하한이 1 이상임을 증명하기 까다롭다.

### 초기 예제도 실습형으로 (05 XDP)

05(XDP 집계)는 실습형으로도 제공한다. `xdp.bpf.c` 의 IPv4 파싱 부분이 TODO 로
비어 있고, `make 05-check` 로 채점한다(ICMP/TCP 집계가 되는지). 채우기 전엔
IPv4 가 안 잡히고, 경계 검사(`data_end`)를 빼면 verifier 가 거부한다 — XDP 의
핵심 감각을 직접 얻는 지점이다. 정답은 `examples/05-xdp-count/solution/`.

같은 패턴으로 다른 초기 예제도 스캐폴드화할 수 있다: 원본을 `solution/` 에
복사하고, 핵심 로직을 TODO 로 비운 뒤 `check.sh` 를 붙이면 된다.

---

## 8. 디버깅하는 법

eBPF 개발 시간의 절반은 디버깅이다. 도구를 알면 시간이 줄어든다.

### 7.1 verifier가 거부할 때 (가장 흔함)

에러 로그가 수백 줄 나온다. **당황하지 말고 맨 끝부터 읽는다.**

```go
var objs auditObjects
if err := loadAuditObjects(&objs, nil); err != nil {
    var ve *ebpf.VerifierError
    if errors.As(err, &ve) {
        log.Fatalf("verifier 거부:\n%+v", ve)   // %+v 라야 로그가 안 잘린다
    }
    log.Fatalf("로드 실패: %v", err)
}
```

자주 나오는 메시지와 원인:

| 메시지 | 원인 | 고치는 법 |
|---|---|---|
| `invalid mem access 'inv'` | 경계 검사 없이 패킷 접근 | `if (ptr + 1 > data_end) return ...` 추가 |
| `R1 type=map_value_or_null expected=map_value` | 맵 lookup 결과 NULL 검사 안 함 | `if (!v) return 0;` |
| `math between pkt pointer and register` | 포인터 산술이 verifier가 추적 못 하는 형태 | 오프셋을 상수로 만들거나 `bpf_skb_load_bytes` 사용 |
| `back-edge from insn X to Y` | 루프를 verifier가 못 푼다 | `#pragma unroll` 또는 `bpf_loop()` |
| `stack limit exceeded` | 지역 변수가 512바이트 초과 | 구조체를 PERCPU_ARRAY 맵에 담아 쓴다 |
| `func 'xxx' not found in kernel BTF` | fentry 대상 함수가 없거나 인라인됨 | kprobe로 대체하거나 다른 함수 선택 |

### 7.2 `bpf_printk`로 커널에서 출력하기

```c
bpf_printk("daddr=%x dport=%d", e->daddr, e->dport);
```

```bash
make trace      # /sys/kernel/debug/tracing/trace_pipe 를 읽는다
```

**주의**: 느리고, 인자 3개까지만 되고, 프로덕션에는 절대 남기면 안 된다.
개발 중에만 쓴다.

### 7.3 bpftool — 커널에 뭐가 올라가 있는지 본다

```bash
make progs      # 로드된 프로그램 목록
make maps       # 맵 목록
make links      # bpf_link — 어디에 붙어 있는지 (이게 제일 유용하다)

# 맵 내용 직접 덤프
docker compose exec lab bpftool map dump id 123
docker compose exec lab bpftool map dump pinned /sys/fs/bpf/ebpf-audit/stats

# 프로그램의 JIT 어셈블리 보기
docker compose exec lab bpftool prog dump jited id 123

# 이 커널이 지원하는 기능 전수 조사
docker compose exec lab bpftool feature probe | less
```

**"예제를 껐는데 프로그램이 남아있다"** 싶으면 `make links`로 확인한다.
프로세스가 살아있으면 링크도 살아있다. 프로세스를 죽이면 자동 해제된다.

### 7.4 bpftrace — 짜기 전에 먼저 탐색

Go로 30줄 짜기 전에, bpftrace 한 줄로 "이 훅이 실제로 불리긴 하나"를 확인하는 게 빠르다.

```bash
# 붙을 수 있는 함수 찾기 (bpftrace 0.20은 fentry를 kfunc라고 부른다)
docker compose exec lab bpftrace -l 'kfunc:tcp_*' | head
docker compose exec lab bpftrace -l 'tracepoint:syscalls:sys_enter_open*'
docker compose exec lab bpftrace -l 'kprobe:do_unlink*'

# 01번 예제와 같은 일을 한 줄로
docker compose exec lab bpftrace -e \
  'kprobe:do_unlinkat { printf("%-16s %s\n", comm, str(((struct filename *)arg1)->name)); }'

# 시스템콜 빈도 히스토그램
docker compose exec lab bpftrace -e \
  'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# 함수 지연시간 분포
docker compose exec lab bpftrace -e \
  'kprobe:vfs_read { @s[tid] = nsecs; }
   kretprobe:vfs_read /@s[tid]/ { @ns = hist(nsecs - @s[tid]); delete(@s[tid]); }'
```

**탐색은 bpftrace, 제품은 Go.** 이게 실무 분업이다.
bpftrace는 배포하려면 대상 서버에 bpftrace와 커널 헤더가 있어야 하지만,
cilium/ebpf로 만든 Go 바이너리는 그냥 복사해서 실행하면 된다.

### 7.5 심볼과 타입 찾기

```bash
make sh

# 이 커널에 그 함수가 있나?
grep ' t do_unlinkat$' /proc/kallsyms
grep -c ' [tT] ' /proc/kallsyms          # 전체 함수 개수

# 구조체 정의 확인 (vmlinux.h가 15만 줄이라 grep이 빠르다)
grep -n 'struct sock_common {' -A 40 /lab/include/vmlinux.h

# BPF 헬퍼 함수 전체 목록 — 시그니처와 설명이 주석으로 다 있다
less /usr/include/bpf/bpf_helper_defs.h

# 커널 BTF에서 함수 시그니처 확인
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A3 'tcp_connect'
```

---

## 9. 실무에서 걸리는 함정들

이 랩을 만들면서 **실제로 부딪힌** 것들이다. 다 해결해서 코드에 반영했지만,
같은 문제를 실무에서 다시 만나게 되므로 이유를 알아두는 게 좋다.

### uprobe 는 macOS 바인드 마운트 위 파일에 못 붙는다
`/lab` 은 virtiofs(`fakeowner`) 마운트라 `perf_event_open` 이 **EIO** 로 실패한다.
그래서 04번의 타깃은 컨테이너 로컬 overlayfs (`/opt/lab/bin/workload`) 로 빌드한다.
직접 확인:
```bash
docker compose exec lab stat -f -c %T /lab              # UNKNOWN (virtiofs)
docker compose exec lab stat -f -c %T /opt/lab/bin      # overlayfs
```
실무 대응: 컨테이너 안 프로세스에 uprobe 를 붙일 때는 대상 바이너리가 어떤
파일시스템에 있는지 확인해야 한다. NFS 등 일부 파일시스템도 uprobe 를 지원하지 않는다.

### cgroup 네임스페이스가 격리되면 컨테이너 귀속이 안 된다
`compose.yaml` 의 `cgroup: host` 가 없으면 `/sys/fs/cgroup` 에 자기 cgroup 만 보여서
07번이 다른 컨테이너를 못 찾는다. K8s DaemonSet 으로 배포할 때 같은 문제가 생긴다
(`hostPID`, `hostNetwork`, cgroup 볼륨 마운트를 챙겨야 하는 이유).

### 시스템콜 심볼 이름은 아키텍처마다 다르다
`__arm64_sys_openat` vs `__x64_sys_openat`. kprobe 로 시스템콜을 잡으려면
아키텍처 분기가 필요하다. tracepoint 나 fentry 를 쓰면 이 문제가 사라진다.

### `bpf_ktime_get_ns()` 는 벽시계가 아니다
`CLOCK_MONOTONIC` 기준 나노초다. 로그에 시각을 찍으려면
`clock_gettime(CLOCK_MONOTONIC)` 과 현재 시각의 차이로 오프셋을 구해야 한다
(07번 `monotonicToWallOffset()`). 이걸 안 하면 대시보드 시각이 전부 틀어진다.

### exec 시점의 `comm` 은 새 프로세스 이름이 아니다
`sys_enter_execve` 에서는 아직 새 이미지가 로드되지 않았으므로 `comm` 은
실행을 요청한 쪽(보통 셸)이다. 07번 출력의 `sh -> /usr/bin/wget` 이 그 예다.
새 이름이 필요하면 `sched_process_exec` tracepoint 를 써야 한다.

### 링버퍼 유실은 조용히 일어난다
`bpf_ringbuf_reserve()` 가 NULL 을 리턴하면 그 이벤트는 그냥 사라진다.
반드시 세서 노출해야 한다. 07번의 `-metrics` 로 `dropped_total` 확인.

---

## 10. Cilium 실습

**이미 구축되어 실행 중이다.** 클러스터 `cilium-lab` 이 떠 있고 정책 실습 3종이
전부 동작하는 것까지 확인했다.

| 구성 요소 | 버전 |
|---|---|
| kind | v0.32.0 (노드 이미지 `kindest/node:v1.36.1`) |
| Kubernetes | v1.36.1, control-plane 1 + worker 2 |
| Cilium | **v1.20.0** (`KubeProxyReplacement: True`) |
| cilium-cli / hubble | v0.19.7 / v1.19.4 |
| 데이터패스 | Tunnel(vxlan), Host Routing **BPF**, Masquerading **BPF** |

**kube-proxy 가 아예 없다.** Service ClusterIP 변환이 iptables 규칙이 아니라
BPF 맵 조회로 처리된다. Cilium 이 이 노드에 올린 BPF 프로그램은 `cil_*` 93개,
`/sys/fs/bpf/tc/globals/` 에 pin 된 맵은 38개다.

```bash
make cilium-status      # Cilium 요약 (KubeProxyReplacement: True)
make cilium-bpf         # 로드된 cil_* 프로그램 + pin 된 맵 목록
make cilium-lb          # eBPF 로드밸런서 테이블 = kube-proxy 를 대체한 그 맵
make cilium-ct          # BPF conntrack 테이블
make cilium-identity    # 라벨 -> identity 숫자 매핑 (정책 맵의 키)
make cilium-fqdn        # DNS 정책이 학습한 도메인 -> IP 캐시
make cilium-demo        # L3/L4 정책 적용 전/후를 한 번에 비교
make hubble             # Hubble 포트포워딩 (다른 터미널에서 hubble observe -f)
make cilium-ctx         # 지금 어느 클러스터를 보고 있는지
make cilium-down        # 클러스터 삭제 + 원래 컨텍스트 복구
```

### ⚠️ kubectl 컨텍스트가 바뀌어 있다

`kind create cluster` 는 현재 컨텍스트를 자기 것으로 바꾼다. 실습 시작 전 컨텍스트는
`cilium/.prev-context` 에 저장해 뒀고, `make cilium-down` 이 자동으로 되돌린다.
지금 당장 원래 클러스터를 봐야 하면:

```bash
make cilium-ctx                                   # 현황 확인
kubectl config use-context "$(cat cilium/.prev-context)"   # 원래대로
kubectl config use-context kind-cilium-lab                 # 다시 실습으로
```

### 검증된 실습 결과

세 가지 정책이 실제로 동작하는 것을 확인했다:

```
정책 없음        xwing "Ship landed" / tiefighter "Ship landed"
L3/L4 정책       xwing 타임아웃(커널에서 드롭) / tiefighter "Ship landed"
L7 HTTP 정책     POST /v1/request-landing "Ship landed"
                 PUT  /v1/exhaust-port    "Access denied"  (Envoy 가 만든 403)
DNS egress 정책  example.com 200 / github.com 타임아웃
```

Hubble 로 본 드롭 (IP 가 아니라 **identity 숫자**로 판정된다):
```
default/xwing:56376 (ID:3049) <> default/deathstar-...:80 (ID:21579) Policy denied DROPPED (TCP Flags: SYN)
```

**실습 과제는 [`cilium/exercises.md`](cilium/exercises.md)** 에 순서대로 있다:
BPF 맵 직접 열어보기 → Service 로드밸런싱 테이블 → 라벨/identity 매핑 →
L3/L4 정책 → L7 HTTP 정책과 그 비용 → DNS egress 정책.

07번 예제에서 만든 구조(ringbuf → 유저 공간 → 관측)가 Hubble 과 완전히 같다는 걸
확인하는 것이 이 파트의 목표다.

### 구축 중 실제로 걸렸던 문제 (setup.sh 에 반영됨)

**클러스터 안에서 외부 이름이 전부 SERVFAIL 이었다.** kind 노드의
`/etc/resolv.conf` 는 Docker Desktop 내부 리졸버 `192.168.65.254` 를 가리키는데,
이 주소는 노드의 호스트 netns 에서는 응답하지만 **파드 네트워크에서는 응답하지
않는다.** coredns 가 그쪽으로 포워딩하니 클러스터 전체 DNS 가 죽었다.
`setup.sh` 가 coredns 업스트림을 `1.1.1.1 / 8.8.8.8` 로 바꾼다.

교훈: "DNS 가 안 된다" 를 만났을 때 파드→외부 egress 자체가 죽은 건지,
DNS 업스트림만 죽은 건지 분리해서 확인해야 한다. 여기서는 파드에서
`curl http://1.1.1.1` 이 301 을 돌려주는 것으로 egress 는 멀쩡함을 먼저 확인했다.

---

---

## 11. 학습 로드맵 5주

하루 1~2시간 기준. **읽기만 하지 말고 반드시 고쳐볼 것.**
각 주차 끝에 "완료 기준"을 뒀다. 그걸 남한테 설명할 수 있으면 넘어간다.

### 1주차 — 트레이싱 기본기

| 일 | 할 일 | 난이도 |
|---|---|---|
| 1 | README 4장(개념) 읽기 → `make check` → `make 01` 실행하고 출력 이해하기 | 읽기 |
| 2 | `unlink.bpf.c` 한 줄씩 읽기 + **01번 Lv1** (UID 필드 추가) | Lv1 |
| 3 | **01번 Lv2**(버퍼 크기) → **Lv3**(커널 필터링). 여기서 verifier를 처음 만난다 | Lv2~3 |
| 4 | `make 02` — tracepoint `format` 파일 읽기 + **02번 Lv1**(출력만 수정) | 읽기+Lv1 |
| 5 | **02번 Lv2**(키에 UID) → **Lv3**(실패한 openat 세기) | Lv2~3 |
| 6 | `make 03` — **03번 Lv1**(소켓 상태) + **Lv2**(일부러 verifier에게 혼나기) | Lv1~2 |
| 7 | 복습 + bpftrace로 훑어보기(8.4절). 여유 있으면 **01번 Lv4**(`vfs_write`) 도전 | 정리 |

**완료 기준**
- kprobe / tracepoint / fentry 중 뭘 골라야 하는지 상황별로 말할 수 있다
- ringbuf와 해시맵 집계를 언제 각각 쓰는지 말할 수 있다
- verifier 에러 메시지를 보고 어디를 고쳐야 하는지 감이 온다

### 2주차 — 유저 공간과 네트워킹

| 일 | 할 일 | 난이도 |
|---|---|---|
| 1 | `make 04` — Go regabi, uretprobe 금지 이유 + **04번 Lv1**(내 함수 추가) | 읽기+Lv1 |
| 2 | **04번 Lv2**(인자 2개) → **Lv3**(bash에 붙여 포인터 읽기) | Lv2~3 |
| 3 | `make 05` — XDP 경계 검사 + **05번 Lv1~Lv2**(통계 추가, 출발지 IP) | Lv1~2 |
| 4 | **05번 Lv3 — ICMP를 DROP 해서 실제로 ping 막아보기** | Lv3 |
| 5 | **05번 Lv4** — 가변 IP 헤더 파싱 (2주차 최고 난이도, 하루 잡을 것) | Lv4 |
| 6 | `make 06` — TCX vs XDP 차이 정리 + **06번 Lv1~Lv2** | Lv1~2 |
| 7 | **06번 Lv3**(egress 드롭) + `make progs`/`make links`로 커널 상태 관찰 | Lv3 |

**완료 기준**
- 패킷 파싱 코드를 verifier가 통과하도록 직접 짤 수 있다
- XDP / TC / TCX 중 어디에 붙일지 판단 기준을 말할 수 있다
- uprobe로 임의의 바이너리 함수에 붙일 수 있다

### 3주차 — 실무 구조 (여기가 핵심)

| 일 | 할 일 | 난이도 |
|---|---|---|
| 1 | `make 07` → `-json`, `-metrics`, `-container` 다 써보기 + **Lv1**(통계 추가) | 읽기+Lv1 |
| 2 | `audit.bpf.c` 정독 — 커널 필터링(`allowed()`)이 왜 있는지 | 읽기 |
| 3 | `container.go` 정독 + cgroup id = inode 직접 확인 | 읽기 |
| 4 | **07번 Lv2** — ringbuf를 줄여 `dropped`를 직접 만들어보기 | Lv2 |
| 5 | **07번 Lv3** — `sched_process_exec`로 교체 (`__data_loc` 처리) | Lv3 |
| 6 | **07번 Lv4** — LSM 훅으로 실제 차단 | Lv4 |
| 7 | **Lv5 — 자기만의 8번 예제**를 빈 디렉토리에서 시작 (아이디어는 아래) | Lv5 |

```bash
# 3일차 확인용 — cgroup id가 정말 inode인지
docker compose exec lab bash -c \
  'stat -c "%i %n" /sys/fs/cgroup/docker/* | head -3'
make 07 ARGS="-json" | head -3     # cgroup_id 값과 비교
```

**8번 예제 아이디어** (하나 골라서 처음부터 끝까지):
- 파일 무결성 감시: 특정 경로 하위의 write/unlink/rename을 전부 기록
- DNS 스니퍼: `udp_sendmsg` 후킹해서 질의 도메인 추출
- 프로세스 계보 추적: `sched_process_fork`로 부모-자식 트리 구성
- TCP 지연 측정: `tcp_connect` → `tcp_rcv_state_process`까지 시간 (fentry + 해시맵)

**완료 기준**
- 여러 프로브를 하나의 오브젝트로 묶어 관리할 수 있다
- 커널 필터링과 유실 카운팅이 왜 필요한지 설명할 수 있다
- 컨테이너/파드 단위로 이벤트를 귀속시킬 수 있다
- 처음부터 끝까지 자기 도구를 하나 만들었다

### 4주차 — 보안 게임 트랙 (직접 채우기)

여기서 관측을 넘어 **변조·차단·탐지**로 넘어간다. 각 게임은 TODO 를 채우고
`make NN-check` 로 점수를 딴다. 70점 이상이면 클리어.

| 일 | 할 일 | 채점 |
|---|---|---|
| 1 | 08 로 패킷 변조 체험(TTL/DNAT) + 체크섬이 왜 중요한지 | — |
| 2 | **09 변조 탐지**: TTL 불변식 TODO 채우기 | `make 09-check` |
| 3 | **11 XDP DDoS**: SYN 레이트 리밋 TODO 채우기 | `make 11-check` |
| 4 | **10 LSM 차단** + **13 미니 백신**: 실행/파일 차단 | `make 10-check` / `make 13-check` |
| 5 | **12 안티치트**(uprobe) + **14 IDS/IPS**(시그니처) | `make 12-check` / `make 14-check` |
| 6~7 | 각 게임의 💡 확장 아이디어 하나씩 구현 (blocklist, 다중 시그니처 등) | 재채점 |

**완료 기준**
- 관측/집계와 변조/차단/탐지의 차이를 구체적으로 말할 수 있다
- verifier 가 거부하는 패턴(zero-sized read, 경계 검사 누락)을 만나고 스스로 고쳤다
- LSM 으로 커널에서 실제로 무언가를 막아봤다
- 게임 6개를 모두 클리어(70점+)했다

### 5주차 — Cilium

| 일 | 할 일 |
|---|---|
| 1 | `cilium/exercises.md` 0~1번: kube-proxy 없는 클러스터 확인, BPF 맵 직접 보기 |
| 2 | 2~3번: LB 테이블, 라벨 → identity 매핑 |
| 3 | 4번: L3/L4 정책 + Hubble로 드롭 관찰 (`make cilium-demo`) |
| 4 | 5번: L7 HTTP 정책. Envoy가 개입하는 지점과 그 비용 |
| 5 | 6번: DNS egress 정책 + 디버깅 순서 익히기 |
| 6 | Cilium 소스 읽기: `bpf/bpf_lxc.c` — 01~06과 **같은 문법**이라는 걸 확인 |
| 7 | `pkg/datapath/loader` 읽기 — 우리가 `link.AttachTCX`로 한 것의 프로덕션 버전 |

**완료 기준**
- kube-proxy를 BPF가 대체한다는 게 구체적으로 무슨 뜻인지 맵을 짚어가며 설명할 수 있다
- 라벨 → identity → BPF 정책 맵의 간접층이 왜 필요한지 말할 수 있다
- L7 정책의 비용(Envoy 경유)을 알고 언제 쓸지 판단할 수 있다
- Cilium 소스에서 데이터패스 코드를 찾아 읽을 수 있다

### 그 다음

- **Tetragon** — 07번과 같은 구조의 실제 제품. 소스를 읽으면 07번이 뭘 생략했는지 보인다
- **libbpf(C)** — 옆 디렉토리 `../bpf-developer-tutorial`에 48개 예제가 있다.
  Go 대신 C로 같은 걸 해보면 cilium/ebpf가 뭘 대신 해주고 있는지 알게 된다
- **커널 소스** — `kernel/bpf/verifier.c`(1만 줄이 넘지만 주석이 좋다),
  `net/core/filter.c`(헬퍼 함수 구현체)
- **BPF LSM / 보안** — 관찰을 넘어 차단으로. `CONFIG_BPF_LSM=y`라 이 랩에서 가능하다

---

## 12. 명령어 레퍼런스

`make help`로 언제든 볼 수 있다.

### 환경

| 명령 | 설명 |
|---|---|
| `make image` | 실습 이미지 빌드 (clang/llvm/bpftool/go) |
| `make up` / `make down` | 컨테이너 기동 / 정지·삭제 |
| `make setup` | 최초 1회: vmlinux.h + 의존성 + 코드 생성 + 타깃 빌드 |
| `make check` | 커널 기능/권한 점검 (38개 항목) |
| `make sh` | 실습 컨테이너 셸 |
| `make victim-sh` | 트레이싱 대상 컨테이너 셸 |

### 빌드

| 명령 | 설명 |
|---|---|
| `make vmlinux` | 커널 BTF → `include/vmlinux.h` |
| `make generate` | bpf2go 실행 (`.bpf.c` → `.o` + Go 바인딩) |
| `make build` | 전체 예제를 `bin/`으로 빌드 |
| `make workload` | uprobe 타깃 빌드 (`/opt/lab/bin/workload`) |
| `make vet` | `go vet` |
| `make clean` / `make distclean` | 생성물 삭제 / vmlinux.h까지 삭제 |

### 예제 실행

| 명령 | 설명 |
|---|---|
| `make list` | 예제 목록 |
| `make 01` ~ `make 07` | 학습 예제 실행 |
| `make 07 ARGS="-json"` | 인자 전달 |
| `make noise` | 이벤트를 인위적으로 발생 (다른 터미널에서) |

### 게임 트랙 (08~14)

| 명령 | 설명 |
|---|---|
| `make 08` ~ `make 14` | 게임 실행 (심판/도구) |
| `make 05-check` | 05 XDP 실습형 자동 채점 |
| `make 09-check` ~ `make 14-check` | 게임 자동 채점 (점수제 스코어카드) |
| `make game` | 12 안티치트용 게임 타깃 빌드 |

각 게임은 `examples/NN-*/` 의 `.bpf.c` TODO 를 채우고 `make NN-check` 로 채점한다.
정답은 같은 폴더의 `solution/` 에 있다.

### 관찰

| 명령 | 설명 |
|---|---|
| `make progs` / `make maps` / `make links` | 로드된 프로그램 / 맵 / 링크 |
| `make trace` | `bpf_printk` 출력 (trace_pipe) |

### Cilium

| 명령 | 설명 |
|---|---|
| `make cilium-up` / `make cilium-down` | 클러스터 구축 / 삭제(+컨텍스트 복구) |
| `make cilium-status` | Cilium 상태 요약 |
| `make cilium-bpf` | 로드된 `cil_*` 프로그램 + pin된 맵 |
| `make cilium-lb` | eBPF 로드밸런서 테이블 |
| `make cilium-ct` | BPF conntrack 테이블 |
| `make cilium-identity` | 라벨 → identity 숫자 매핑 |
| `make cilium-fqdn` | DNS 정책이 학습한 도메인 → IP 캐시 |
| `make cilium-demo` | L3/L4 정책 적용 전/후 비교 |
| `make cilium-ctx` | kubectl 컨텍스트 현황 |
| `make hubble` | Hubble 포트포워딩 |

---

## 13. 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| `BPF 오브젝트 로드 실패: permission denied` | privileged가 아니다. `make check` 2번 항목 확인 |
| `field XXX: not found in kernel BTF` | `include/vmlinux.h`가 낡음 → `make distclean vmlinux generate` |
| `kprobe 부착 실패: no such file or directory` | 심볼이 없다 → `docker compose exec lab grep ' t 심볼명$' /proc/kallsyms` |
| `fentry 부착 실패` | BTF FUNC에 없거나 인라인됨 → kprobe로 대체 |
| uprobe `input/output error` | 타깃이 `/lab`(virtiofs) 위에 있다 → 9장 함정 절 참고 |
| verifier 거부 (긴 로그) | 8.1절 표에서 메시지 찾기. 대부분 경계 검사/NULL 검사 누락 |
| `make generate` 실패 | `include/vmlinux.h` 없음 → `make vmlinux` 먼저 |
| 예제 종료 후에도 프로그램이 남음 | `make links`로 확인. 프로세스가 살아있으면 링크도 산다 |
| 컨테이너가 이상함 | `make down && make up && make setup` |
| Cilium 파드가 Pending | 이미지 pull 중일 수 있다. `kubectl -n kube-system get events` 확인 |
| 클러스터에서 외부 DNS 실패 | 10장 "구축 중 실제로 걸렸던 문제" 참고 (setup.sh가 이미 처리) |
| `kubectl`이 엉뚱한 클러스터를 봄 | `make cilium-ctx`로 확인하고 전환 |

**완전 초기화:**

```bash
make down && make distclean     # eBPF 랩
make cilium-down                # Cilium 클러스터 (+ 원래 컨텍스트 복구)

make image && make setup        # 다시 만들기
make cilium-up
```

---

## 14. 더 읽을 것

**문서**
- [ebpf-go.dev](https://ebpf-go.dev/) — cilium/ebpf 공식 문서. 이 랩이 쓰는 라이브러리
- [docs.kernel.org/bpf](https://docs.kernel.org/bpf/) — 커널 BPF 문서 (원전)
- [docs.cilium.io](https://docs.cilium.io/) — Cilium 문서. BPF 참고자료 페이지가 특히 좋다
- [ebpf.io](https://ebpf.io/) — 개념 소개와 프로젝트 지도

**이 랩 안에서**
```bash
# BPF 헬퍼 함수 전체 목록 (시그니처 + 설명 주석)
docker compose exec lab less /usr/include/bpf/bpf_helper_defs.h

# 이 커널이 지원하는 기능 전수 조사
docker compose exec lab bpftool feature probe | less

# 커널 타입 정의 (15만 줄)
grep -n 'struct sock_common {' -A 40 include/vmlinux.h
```

**옆 디렉토리**
- `../bpf-developer-tutorial` — libbpf(C) 기반 48개 예제.
  같은 걸 C로 해보면 cilium/ebpf가 뭘 대신 해주는지 알게 된다
- `../linux` — 커널 소스. `kernel/bpf/verifier.c`, `net/core/filter.c`

**책 / 강의**
- *Learning eBPF* (Liz Rice, O'Reilly) — 입문서 중 가장 최신이고 정확하다
- *BPF Performance Tools* (Brendan Gregg) — bpftrace 중심, 성능 분석 레시피 모음

**읽을 만한 실제 코드**
- [Cilium](https://github.com/cilium/cilium) — `bpf/bpf_lxc.c`(데이터패스), `pkg/datapath/loader`(Go 로더)
- [Tetragon](https://github.com/cilium/tetragon) — 07번 예제의 완성형
- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) — 최소 예제 모음

---

## 부록: 이 랩의 현재 상태

```
[eBPF 랩]      ebpf-lab, ebpf-victim 컨테이너 실행 중
               학습 예제 01~07 + 보안 게임 08~14 전부 동작 검증 완료
               게임은 빈칸(TODO) 상태로 출고, 정답은 각 solution/ 에
               make check → 38/38 통과 / 각 게임 solution → 채점 만점 확인

[Cilium 랩]    kind 클러스터 cilium-lab (3노드) 실행 중
               Cilium v1.20.0, KubeProxyReplacement: True
               Star Wars 데모 앱 배포됨, 정책은 적용 안 된 기준선 상태
               정책 실습 3종(L3L4 / L7 HTTP / DNS egress) 동작 검증 완료

[주의]         kubectl 컨텍스트가 kind-cilium-lab 로 바뀌어 있다
               원래 컨텍스트는 cilium/.prev-context 에 저장됨
               make cilium-ctx 로 확인, make cilium-down 하면 자동 복구
```
