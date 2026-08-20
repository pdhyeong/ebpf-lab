# 00. 훅 사냥 (Hook Hunting)

> **"어디에 붙일 것인가"가 eBPF 개발의 8할이다.**
> 01~14 는 훅을 정한 뒤의 이야기다. 이 랩은 그 앞 단계만 훈련한다.
> 코드는 한 줄도 안 쓴다. **찾고, 확인하고, 답을 적는다.**

## 진행 방법

```bash
make hunt          # 이 문서를 연다
# examples/00-hunt/answers.txt 를 채운다
make hunt-check    # 채점 (10문제 × 10점, 70점 통과)
```

## 채점 방식

두 단계로 검증한다.

1. **존재 검증** — 네가 적은 훅이 **이 커널에 실제로 존재하는가**를 확인한다.
   없는 걸 적으면 정답 여부를 보기 전에 여기서 걸린다.
   (코드를 쓰기 전에 대상이 있는지 확인하는 습관이 이 랩의 목적이다)
2. **정답 검증** — 목표에 맞는 훅인지 본다. **정답이 여러 개인 문제도 있다.**

## 답안 형식

`answers.txt` 에 이렇게 적는다:

```
1 = tracepoint syscalls/sys_enter_openat
2 = kprobe do_unlinkat
3 = fentry tcp_connect
4 = uprobe main.compute
5 = lsm file_open
6 = tc
```

| 훅 종류 | 적는 법 | 예 |
|---|---|---|
| tracepoint | `tracepoint <그룹>/<이벤트>` | `tracepoint syscalls/sys_enter_openat` |
| kprobe | `kprobe <커널함수>` | `kprobe do_unlinkat` |
| fentry / fexit | `fentry <커널함수>` | `fentry tcp_connect` |
| uprobe | `uprobe <심볼>` | `uprobe main.compute` |
| LSM | `lsm <훅이름>` | `lsm file_open` |
| XDP | `xdp` | `xdp` |
| TC / TCX | `tc` | `tc` |

---

## 탐색 도구

**이 명령들만 알면 다 찾을 수 있다.**

```bash
make sh    # 컨테이너 안에서

# ── tracepoint 찾기 (있으면 무조건 이걸 쓴다. 가장 안 깨진다)
ls /sys/kernel/debug/tracing/events/                    # 그룹 목록
ls /sys/kernel/debug/tracing/events/syscalls/ | grep X  # 시스템콜
ls /sys/kernel/debug/tracing/events/sched/              # 스케줄러 이벤트
cat /sys/kernel/debug/tracing/events/<그룹>/<이벤트>/format   # 인자 레이아웃

# ── fentry 대상 찾기 (BTF 에 있는 커널 함수. tracepoint 다음 선택지)
bpftrace -l 'kfunc:*tcp*' | head            # 0.20 은 fentry 를 kfunc 라 부른다
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -w '<함수>'

# ── kprobe 대상 찾기 (마지막 수단. 커널 바뀌면 깨진다)
grep ' [tT] <함수>$' /proc/kallsyms

# ── LSM 훅 찾기 (차단하려면 여기)
grep ' [tT] bpf_lsm_' /proc/kallsyms | head -40

# ── uprobe 대상 찾기 (유저 공간 바이너리)
go tool nm /opt/lab/bin/workload | grep <심볼>
nm -D /usr/lib/aarch64-linux-gnu/libssl.so.3 | grep SSL_write

# ── 이 커널이 지원하는 프로그램 타입
bpftool feature probe | grep -i 'program_type'
```

---

## 선택 기준 (막히면 이 순서로)

```
1) 관찰인가 차단인가?
     차단 -> LSM (파일/실행/소켓) 또는 XDP/TC (패킷)
     관찰 -> 2번으로

2) 네트워크 패킷인가?
     ingress 만, 최고속  -> XDP
     양방향, 메타데이터  -> TC / TCX
     아니면 -> 3번으로

3) 유저 공간 함수인가?
     -> uprobe

4) 커널이다. tracepoint 가 있나?
     ls /sys/kernel/debug/tracing/events/
     있다 -> tracepoint  (ABI 로 유지된다. 최우선)

5) 없다. BTF 에 그 함수가 있나?
     bpftrace -l 'kfunc:*이름*'
     있다 -> fentry  (타입 안전 + 빠름)

6) 그것도 없다 -> kprobe  (커널 버전마다 깨질 각오)
```

---

# 목표 10개

각 목표에 대해 **어디에 붙을지** 답하라.

### 1. 프로세스가 파일을 여는 순간을 관측하라
> 힌트: 시스템콜이다. 시스템콜은 kprobe 를 쓰면 안 되는 이유가 있었다.

### 2. 파일이 삭제되는 순간을 관측하라
> 힌트: `unlink(2)` 와 `unlinkat(2)` 두 시스템콜이 있다.
> 둘을 각각 잡을 수도 있고, 공통 구현부 하나만 잡을 수도 있다. **둘 다 정답이다.**

### 3. 새 프로그램이 실행(exec)되는 순간을 관측하라
> 힌트: 시스템콜 진입 시점도 있고, 스케줄러 그룹(`sched/`)에도 관련 이벤트가 있다.
> `ls /sys/kernel/debug/tracing/events/sched/`

### 4. 프로세스가 TCP 연결을 맺으러 나가는 순간을 관측하라
> 힌트: `connect(2)` 시스템콜은 유저가 부르는 입구일 뿐이다.
> **실제로 SYN 을 보내는 커널 함수**를 잡아야 목적지 IP/포트를 구조체로 얻는다.
> 이 지점에는 tracepoint 가 없다. 다음 선택지로 가라.

### 5. 프로세스가 종료되는 순간을 관측하라
> 힌트: 시스템콜(`exit_group`)로도 되지만, 커널이 **정확히 그 목적으로** 만들어 둔
> 스케줄러 tracepoint 가 있다. 그쪽이 더 정확하다.

### 6. 새 프로세스가 fork 되는 순간을 관측하라
> 힌트: 5번과 같은 그룹에 있다.

### 7. `/opt/lab/bin/workload` 의 `main.compute` 함수 호출을 관측하라
> 힌트: 커널이 아니다. 대상은 **파일의 심볼**이다.
> `go tool nm` 으로 심볼이 실제 있는지 먼저 확인하라.

### 8. 특정 프로그램의 **실행을 차단**하라 (관찰이 아니라 거부)
> 힌트: 관찰용 훅은 반환값이 무시된다. **결정 지점**에 있는 훅이어야 한다.
> `grep ' [tT] bpf_lsm_bprm' /proc/kallsyms`

### 9. 특정 파일의 **열기를 차단**하라
> 힌트: 8번과 같은 계열. 훅 이름만 다르다.
> `grep ' [tT] bpf_lsm_file' /proc/kallsyms`

### 10. 인터페이스에서 **나가는(egress)** 패킷을 관측하라
> 힌트: 가장 빠른 네트워크 훅은 이 목적에 쓸 수 없다. 왜인지 답할 수 있어야 한다.
> `bpftool feature probe | grep -i sched`

---

## 다 풀었으면

```bash
make hunt-check
```

70점을 넘으면 `examples/00-hunt/STUDY.html` 로 훅 선택 기준을 정리하고 `make 01` 로 간다.
