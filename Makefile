# eBPF + Go 실습 랩
#
# 이 Makefile 은 호스트(macOS)에서 실행해도, 컨테이너 안에서 실행해도 동작한다.
#   - 호스트에서 실행하면 모든 명령을 'docker compose exec lab' 으로 감싼다
#   - 컨테이너 안(/.dockerenv 존재)에서는 그대로 실행한다
# 따라서 macOS 터미널에서 'make 01' 만 쳐도 컨테이너 안에서 돌아간다.

SHELL   := /bin/bash
SERVICE := lab
COMPOSE := docker compose

IN_CONTAINER := $(wildcard /.dockerenv)

ifeq ($(IN_CONTAINER),)
  RUN    := $(COMPOSE) exec $(SERVICE)
  ENSURE := $(COMPOSE) up -d >/dev/null
else
  RUN    :=
  ENSURE := true
endif

BPF_SRCS   := $(wildcard examples/*/*.bpf.c)
GEN_STAMPS := $(BPF_SRCS:.bpf.c=.gen-stamp)

# 예제 번호 -> 그 예제의 스탬프 경로.  $(call stamp,02)
#   examples/02-tracepoint-openat/openat.bpf.c -> examples/02-tracepoint-openat/openat.gen-stamp
stamp = $(patsubst %.bpf.c,%.gen-stamp,$(wildcard examples/$(1)-*/*.bpf.c))

.DEFAULT_GOAL := help

# ---------------------------------------------------------------- 환경 관리
.PHONY: help
help: ## 이 도움말
	@printf '\n\033[1meBPF + Go 실습 랩\033[0m\n\n'
	@grep -hE '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@printf '\n처음이면:  \033[1mmake setup\033[0m  ->  \033[1mmake check\033[0m  ->  \033[1mmake 01\033[0m\n\n'

.PHONY: image
image: ## 실습 이미지 빌드 (clang/llvm/bpftool/go)
	$(COMPOSE) build $(SERVICE)

.PHONY: up
up: ## 컨테이너 기동 (lab + victim)
	$(COMPOSE) up -d
	@$(COMPOSE) ps

.PHONY: down
down: ## 컨테이너 정지 및 삭제
	$(COMPOSE) down

.PHONY: sh
sh: ## 컨테이너 셸 진입
	@$(ENSURE)
	$(COMPOSE) exec $(SERVICE) bash

.PHONY: victim-sh
victim-sh: ## 트레이싱 대상(victim) 컨테이너 셸 진입
	@$(ENSURE)
	$(COMPOSE) exec victim sh

.PHONY: setup
setup: up vmlinux deps generate workload ## 최초 1회: vmlinux.h 생성 + 의존성 + 코드 생성 + 타깃 빌드
	@printf '\n\033[32m준비 완료.\033[0m  make check 로 환경 점검 후 make 01 부터 실행.\n'

.PHONY: check
check: ## 커널 기능/권한 점검
	@$(ENSURE)
	$(RUN) bash scripts/check-env.sh

# ---------------------------------------------------------------- 빌드
.PHONY: vmlinux
vmlinux: include/vmlinux.h ## 실행 중인 커널 BTF -> include/vmlinux.h

include/vmlinux.h:
	@$(ENSURE)
	$(RUN) bash -c 'mkdir -p include && bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h'
	@$(RUN) bash -c 'echo "include/vmlinux.h: $$(wc -l < include/vmlinux.h) 줄"'

.PHONY: deps
deps: ## Go 모듈 다운로드
	@$(ENSURE)
	$(RUN) go mod download
	$(RUN) go mod tidy

.PHONY: generate
generate: $(GEN_STAMPS) ## bpf2go 실행: .bpf.c -> .o + Go 바인딩 (바뀐 예제만)

# 예제별 스탬프. 자기 .bpf.c 가 바뀐 예제 하나만 bpf2go(clang) 가 다시 돈다.
# $(@D) 는 스탬프의 디렉터리 = 그 예제의 Go 패키지 경로.
$(GEN_STAMPS): %.gen-stamp: %.bpf.c include/vmlinux.h
	@$(ENSURE)
	$(RUN) go generate ./$(@D)
	@touch $@

.PHONY: build
build: $(GEN_STAMPS) ## 모든 예제를 bin/ 으로 빌드
	@$(ENSURE)
	$(RUN) go build -o bin/ ./examples/... ./target/...
	@$(RUN) ls -la bin/

# 주의: uprobe 는 /lab (macOS 바인드 마운트 = virtiofs) 위의 파일에 붙을 수 없다.
# perf_event_open 이 EIO 로 실패한다. 그래서 타깃 바이너리는 컨테이너 자체
# 파일시스템(overlayfs)인 /opt/lab/bin 으로 빌드한다. README 의 "함정" 절 참고.
WORKLOAD := /opt/lab/bin/workload

.PHONY: workload
workload: ## uprobe 실습용 타깃 프로그램 빌드 (/opt/lab/bin/workload)
	@$(ENSURE)
	$(RUN) bash -c 'mkdir -p $(dir $(WORKLOAD)) && go build -o $(WORKLOAD) ./target/workload && ls -la $(WORKLOAD)'

.PHONY: vet
vet: $(GEN_STAMPS) ## go vet
	@$(ENSURE)
	$(RUN) go vet ./...

.PHONY: clean
clean: ## 생성물 삭제 (vmlinux.h 는 유지)
	@$(ENSURE)
	-$(RUN) bash -c 'rm -f examples/*/*_bpfel.go examples/*/*_bpfeb.go examples/*/*_bpfel.o examples/*/*_bpfeb.o; rm -rf bin'
	@rm -f .gen-stamp examples/*/*.gen-stamp

.PHONY: distclean
distclean: clean ## vmlinux.h 까지 삭제
	@rm -f include/vmlinux.h

# ---------------------------------------------------------------- 예제 실행
.PHONY: list
list: ## 예제 목록
	@printf '\n'
	@printf '  \033[36m01\033[0m  kprobe        do_unlinkat 후킹 -> 파일 삭제 실시간 추적 (ringbuf)\n'
	@printf '  \033[36m02\033[0m  tracepoint    sys_enter_openat -> 프로세스별 openat 집계 (hash map)\n'
	@printf '  \033[36m03\033[0m  fentry/fexit  tcp_connect 후킹 -> TCP 커넥트 추적 (BTF/CO-RE)\n'
	@printf '  \033[36m04\033[0m  uprobe        Go 바이너리의 main.compute 인자 훔쳐보기\n'
	@printf '  \033[36m05\033[0m  XDP           인터페이스 수신 패킷 프로토콜별 집계\n'
	@printf '  \033[36m06\033[0m  TCX           ingress/egress 양방향 집계 (커널 6.6+, 현대 Cilium 방식)\n'
	@printf '  \033[36m07\033[0m  실무형        멀티 프로브 + 컨테이너 속성 + JSON 로그 + Prometheus\n'
	@printf '  \033[36m08\033[0m  TC 변조       loopback 안에서 패킷을 실제로 고쳐 내보내기 (TTL/DNAT)\n'
	@printf '  \033[35m09\033[0m  변조탐지 게임 🔴Red 변조 vs 🔵Blue 탐지 (직접 채우는 챌린지)\n'
	@printf '  \033[35m10\033[0m  LSM 보안 게임 파일/실행을 실제로 차단 (직접 채우는 챌린지)\n'
	@printf '  \033[35m11\033[0m  XDP DDoS 게임 SYN flood 탐지·차단 (직접 채우는 챌린지)\n'
	@printf '  \033[35m12\033[0m  안티치트 게임 uprobe 로 메모리 조작 치트 탐지 (챌린지)\n'
	@printf '  \033[35m13\033[0m  미니백신 게임 시그니처 파일 격리 (LSM, 챌린지)\n'
	@printf '  \033[35m14\033[0m  IDS/IPS 게임  페이로드 시그니처 탐지·차단 (챌린지)\n'
	@printf '\n  \033[36m00\033[0m  훅 사냥       코드 없이 "어디에 붙일지" 만 찾는다  (\033[36mmake hunt\033[0m)\n'
	@printf '\n  실행:  make 01   (make 07 ARGS="-metrics :9101" 처럼 인자 전달 가능)\n'
	@printf '  \033[1m전 랩 공통:\033[0m  .bpf.c 의 TODO 를 Lv1 부터 채우고  \033[36mmake NN-check\033[0m  로 채점 (70점 통과)\n'
	@printf '  통과 후:  \033[36mopen examples/NN-*/STUDY.html\033[0m  (이론 + 동작 해부 + OX 퀴즈)\n\n'

ARGS ?=

.PHONY: 01 02 03 04 05 06 07
01: $(call stamp,01) ## kprobe 예제 실행
	@$(ENSURE)
	$(RUN) go run ./examples/01-kprobe-unlink $(ARGS)

02: $(call stamp,02) ## tracepoint 예제 실행
	@$(ENSURE)
	$(RUN) go run ./examples/02-tracepoint-openat $(ARGS)

03: $(call stamp,03) ## fentry/fexit 예제 실행
	@$(ENSURE)
	$(RUN) go run ./examples/03-fentry-tcpconnect $(ARGS)

04: $(call stamp,04) workload ## uprobe 예제 실행 (타깃 자동 기동)
	@$(ENSURE)
	@$(RUN) bash -c 'pgrep -x workload >/dev/null || { nohup $(WORKLOAD) > /tmp/workload.log 2>&1 & sleep 1; echo "workload 를 백그라운드로 띄웠다 (로그: /tmp/workload.log)"; }'
	$(RUN) go run ./examples/04-uprobe-go $(ARGS)

.PHONY: workload-stop
workload-stop: ## uprobe 타깃 종료
	@$(ENSURE)
	-$(RUN) pkill -x workload

05: $(call stamp,05) ## XDP 예제 실행
	@$(ENSURE)
	$(RUN) go run ./examples/05-xdp-count $(ARGS)

06: $(call stamp,06) ## TCX 예제 실행
	@$(ENSURE)
	$(RUN) go run ./examples/06-tcx-egress $(ARGS)

07: $(call stamp,07) ## 실무형 런타임 감시 에이전트 실행
	@$(ENSURE)
	$(RUN) go run ./examples/07-runtime-audit $(ARGS)

# ---------------------------------------------------------------- 00 훅 사냥
# 코드를 쓰기 전 단계. "어디에 붙일 것인가" 만 훈련한다.
.PHONY: hunt hunt-check
hunt: ## 00 훅 사냥 — 목표 문서 열기 (코드 없이 훅만 찾는다)
	@printf '\n\033[1m00. 훅 사냥\033[0m — 어디에 붙일 것인가만 훈련한다\n\n'
	@printf '  1) 목표 읽기:   \033[36mexamples/00-hunt/TARGETS.md\033[0m\n'
	@printf '  2) 답안 작성:   \033[36mexamples/00-hunt/answers.txt\033[0m\n'
	@printf '  3) 채점:        \033[36mmake hunt-check\033[0m\n'
	@printf '  4) 정리:        \033[36mopen examples/00-hunt/STUDY.html\033[0m\n\n'
	@printf '  탐색은 컨테이너 안에서:  \033[36mmake sh\033[0m\n\n'

hunt-check: ## 00 훅 사냥 채점 (존재 검증 + 정답 검증, 10문제)
	@$(ENSURE)
	$(RUN) bash examples/00-hunt/check.sh

# ---------------------------------------------------------------- 학습 트랙 채점
# 01~07 도 08~14 와 동일한 "빈칸 -> 채점" 방식이다.
#   make NN        예제 실행 (빈칸 상태면 결과가 안 나온다)
#   make NN-check  단계별 자동 채점 (Lv0 빌드 -> Lv1 -> Lv2 -> ... 순차 통과)
#   막히면         examples/NN-*/solution/ 참고
.PHONY: 01-check 02-check 03-check 04-check 06-check 07-check
01-check: ## 01번 자동 채점 (kprobe 단계별)
	@$(ENSURE)
	$(RUN) bash examples/01-kprobe-unlink/check.sh

02-check: ## 02번 자동 채점 (tracepoint 단계별)
	@$(ENSURE)
	$(RUN) bash examples/02-tracepoint-openat/check.sh

03-check: ## 03번 자동 채점 (fentry/fexit 단계별)
	@$(ENSURE)
	$(RUN) bash examples/03-fentry-tcpconnect/check.sh

04-check: ## 04번 자동 채점 (uprobe 단계별)
	@$(ENSURE)
	$(RUN) bash examples/04-uprobe-go/check.sh

06-check: ## 06번 자동 채점 (TCX 단계별)
	@$(ENSURE)
	$(RUN) bash examples/06-tcx-egress/check.sh

07-check: ## 07번 자동 채점 (런타임 감시 에이전트 단계별)
	@$(ENSURE)
	$(RUN) bash examples/07-runtime-audit/check.sh

.PHONY: study
study: ## 각 예제의 STUDY.html 위치 안내 (이론 + OX 퀴즈)
	@printf '\n\033[1m학습 문서 (이론 + 동작 해부 + OX 퀴즈)\033[0m\n\n'
	@ls examples/*/STUDY.html 2>/dev/null | sed 's|^|  open |' || echo '  (아직 없다)'
	@printf '\n  macOS 에서 바로 열기:  open examples/01-kprobe-unlink/STUDY.html\n\n'

.PHONY: 05-check 08 09 10 11 12 13 14 game 09-check 10-check 11-check 12-check 13-check 14-check
08: $(call stamp,08) ## TC 패킷 변조 (변조 도구 = Red 무기)
	@$(ENSURE)
	$(RUN) go run ./examples/08-tc-mangle $(ARGS)

09: $(call stamp,09) ## 변조 탐지 게임 (Blue 심판 실행)
	@$(ENSURE)
	$(RUN) go run ./examples/09-tamper-detect $(ARGS)

10: $(call stamp,10) ## LSM 보안 게임 실행
	@$(ENSURE)
	$(RUN) go run ./examples/10-lsm-guard $(ARGS)

11: $(call stamp,11) ## XDP DDoS 게임 실행
	@$(ENSURE)
	$(RUN) go run ./examples/11-xdp-ddos $(ARGS)

12: $(call stamp,12) game ## 안티치트 게임 실행 (게임 타깃 자동 빌드)
	@$(ENSURE)
	$(RUN) go run ./examples/12-anticheat $(ARGS)

13: $(call stamp,13) ## 미니백신 게임 실행
	@$(ENSURE)
	$(RUN) go run ./examples/13-mini-av $(ARGS)

14: $(call stamp,14) ## IDS/IPS 게임 실행
	@$(ENSURE)
	$(RUN) go run ./examples/14-ids-ips $(ARGS)

game: ## 안티치트 실습용 게임 타깃 빌드 (/opt/lab/bin/game)
	@$(ENSURE)
	$(RUN) bash -c 'mkdir -p /opt/lab/bin && go build -o /opt/lab/bin/game ./target/game && echo "game -> /opt/lab/bin/game"'

12-check: ## 12번 자동 채점
	@$(ENSURE)
	$(RUN) bash examples/12-anticheat/check.sh

13-check: ## 13번 자동 채점
	@$(ENSURE)
	$(RUN) bash examples/13-mini-av/check.sh

14-check: ## 14번 자동 채점
	@$(ENSURE)
	$(RUN) bash examples/14-ids-ips/check.sh

05-check: ## 05번 자동 채점 (XDP 실습형)
	@$(ENSURE)
	$(RUN) bash examples/05-xdp-count/check.sh

09-check: ## 09번 자동 채점 (내 detect.bpf.c 가 공격을 잡나?)
	@$(ENSURE)
	$(RUN) bash examples/09-tamper-detect/check.sh

10-check: ## 10번 자동 채점
	@$(ENSURE)
	$(RUN) bash examples/10-lsm-guard/check.sh

11-check: ## 11번 자동 채점
	@$(ENSURE)
	$(RUN) bash examples/11-xdp-ddos/check.sh

# ---------------------------------------------------------------- 관찰 도구
.PHONY: progs maps links trace noise
progs: ## 커널에 로드된 BPF 프로그램 목록
	@$(ENSURE)
	$(RUN) bpftool prog list

maps: ## BPF 맵 목록
	@$(ENSURE)
	$(RUN) bpftool map list

links: ## bpf_link 목록 (어디에 붙어 있는지)
	@$(ENSURE)
	$(RUN) bpftool link list

trace: ## bpf_printk 출력 보기 (trace_pipe)
	@$(ENSURE)
	$(RUN) bash -c 'cat /sys/kernel/debug/tracing/trace_pipe'

# ---------------------------------------------------------------- Cilium 랩
# 이 타깃들은 호스트(macOS)에서 kind/kubectl/cilium CLI 를 쓴다. 컨테이너 안이 아니다.
CILIUM_POD = kubectl -n kube-system get pod -l k8s-app=cilium -o name | head -1

.PHONY: cilium-up cilium-down cilium-status cilium-bpf cilium-lb cilium-ct hubble cilium-ctx cilium-demo cilium-identity cilium-fqdn
cilium-up: ## kind 클러스터 + Cilium(kube-proxy 대체) + 데모 앱 구축
	bash cilium/setup.sh

cilium-down: ## kind 클러스터 삭제
	bash cilium/teardown.sh

cilium-status: ## Cilium 상태 요약
	cilium status

cilium-bpf: ## Cilium 이 로드한 BPF 프로그램/맵 목록 (agent 파드 안에서)
	@POD=$$($(CILIUM_POD)); echo "== $$POD =="; \
	 total=$$(kubectl -n kube-system exec $$POD -c cilium-agent -- bpftool prog list | grep -cE '^[0-9]+:'); \
	 cil=$$(kubectl -n kube-system exec $$POD -c cilium-agent -- bpftool prog list | grep -cE 'name cil_'); \
	 echo "커널 전체 BPF 프로그램 $$total 개 중 Cilium 소속(cil_*) $$cil 개"; \
	 echo "(kind 노드는 컨테이너라 호스트 커널을 공유한다. 그래서 다른 컨테이너의"; \
	 echo " BPF 프로그램까지 같이 보인다 -- 이것도 알아둘 만한 사실이다)"; echo; \
	 kubectl -n kube-system exec $$POD -c cilium-agent -- bpftool prog list | grep -B0 -E 'name cil_' | head -25; \
	 echo; echo "== pin 된 Cilium 맵 =="; \
	 kubectl -n kube-system exec $$POD -c cilium-agent -- sh -c 'ls /sys/fs/bpf/tc/globals/ | wc -l; ls /sys/fs/bpf/tc/globals/'

cilium-identity: ## 라벨 -> identity 숫자 매핑 (BPF 정책 맵의 키)
	@POD=$$($(CILIUM_POD)); \
	 kubectl -n kube-system exec $$POD -c cilium-agent -- cilium-dbg identity list | head -25

cilium-fqdn: ## DNS 정책이 학습한 도메인 -> IP 캐시
	@for p in $$(kubectl -n kube-system get pod -l k8s-app=cilium -o name); do \
	  echo "== $$p =="; \
	  kubectl -n kube-system exec $$p -c cilium-agent -- cilium-dbg fqdn cache list 2>/dev/null | head -12; \
	done

cilium-lb: ## eBPF 로드밸런서 테이블 (kube-proxy 를 대체한 그 맵)
	@POD=$$($(CILIUM_POD)); \
	 kubectl -n kube-system exec $$POD -c cilium-agent -- cilium-dbg bpf lb list

cilium-ct: ## BPF conntrack 테이블
	@POD=$$($(CILIUM_POD)); \
	 kubectl -n kube-system exec $$POD -c cilium-agent -- cilium-dbg bpf ct list global | head -30

hubble: ## Hubble 관측 포트포워딩 (별도 터미널에서 hubble observe -f)
	cilium hubble port-forward

cilium-ctx: ## kubectl 컨텍스트 현황 (실습용 kind vs 원래 쓰던 클러스터)
	@echo "현재: $$(kubectl config current-context 2>/dev/null || echo '(없음)')"
	@if [ -f cilium/.prev-context ]; then \
	  echo "실습 시작 전: $$(cat cilium/.prev-context)"; \
	  echo; echo "  실습으로:   kubectl config use-context kind-cilium-lab"; \
	  echo "  원래대로:   kubectl config use-context $$(cat cilium/.prev-context)"; \
	  echo "  (make cilium-down 하면 자동으로 원래대로 돌아간다)"; \
	else \
	  echo "저장된 이전 컨텍스트 없음"; \
	fi

cilium-demo: ## L3/L4 정책 실습을 한 번에 실행 (적용 전/후 비교)
	@echo "=== 정책 적용 전: 둘 다 착륙 성공해야 정상 ==="
	-@kubectl exec xwing      -- curl -s -m 5 -XPOST deathstar.default.svc.cluster.local/v1/request-landing
	-@kubectl exec tiefighter -- curl -s -m 5 -XPOST deathstar.default.svc.cluster.local/v1/request-landing
	@echo; echo "=== 정책 적용 ==="
	kubectl apply -f cilium/policies/01-l3-l4.yaml
	@sleep 3
	@echo; echo "=== 적용 후: xwing 은 드롭되어 타임아웃, tiefighter 만 성공 ==="
	-@kubectl exec xwing      -- curl -s -m 5 -XPOST deathstar.default.svc.cluster.local/v1/request-landing || echo "xwing: 차단됨 (정상)"
	-@kubectl exec tiefighter -- curl -s -m 5 -XPOST deathstar.default.svc.cluster.local/v1/request-landing
	@echo; echo "드롭 확인:  make hubble  (다른 터미널)  ->  hubble observe --verdict DROPPED --last 20"
	@echo "정책 해제:  kubectl delete -f cilium/policies/01-l3-l4.yaml"

noise: ## 예제가 잡을 이벤트를 인위적으로 발생시킨다
	@$(ENSURE)
	$(RUN) bash -c 'set -x; \
	  for i in 1 2 3; do touch /tmp/ebpf-test-$$i && rm /tmp/ebpf-test-$$i; done; \
	  ls -R /usr/include/bpf >/dev/null; \
	  ping -c 2 -W 1 1.1.1.1 || true; \
	  (exec 3<>/dev/tcp/example.com/80 && printf "GET / HTTP/1.0\r\n\r\n" >&3 && head -1 <&3) || true'
