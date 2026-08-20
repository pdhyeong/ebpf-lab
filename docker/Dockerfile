# eBPF + Go(cilium/ebpf) 실습용 이미지
#
# Docker Desktop(macOS)의 linuxkit 커널을 그대로 빌려 쓴다.
#   - /sys/kernel/btf/vmlinux 존재 -> CO-RE / fentry 사용 가능
#   - CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y -> fentry/fexit 트램폴린 동작
#   - 커널 6.10 -> TCX(tcx_ingress/egress) 사용 가능
FROM ubuntu:24.04

ARG GO_VERSION=1.26.6
ARG BPFTOOL_REF=v7.5.0
ENV DEBIAN_FRONTEND=noninteractive

# 1) 툴체인
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm lld \
        libbpf-dev libelf-dev zlib1g-dev libcap-dev libzstd-dev \
        build-essential pkg-config make git \
        bpftrace strace ltrace linux-libc-dev \
        iproute2 iputils-ping netcat-openbsd tcpdump ethtool \
        curl wget ca-certificates jq vim less procps bsdmainutils file \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu는 llvm 툴을 버전 접미사로만 깔아준다. 접미사 없는 이름으로 심볼릭 링크.
RUN set -eux; \
    llvmdir="$(ls -d /usr/lib/llvm-* | sort -V | tail -1)"; \
    for t in clang clang++ llvm-strip llvm-objdump llvm-readelf llc opt; do \
        [ -e "/usr/bin/$t" ] || ln -sf "$llvmdir/bin/$t" "/usr/bin/$t"; \
    done; \
    clang --version; llvm-strip --version

# 2) bpftool (우분투 24.04에는 단독 패키지가 없어서 소스 빌드)
RUN set -eux; \
    git clone --depth 1 --recurse-submodules -b "${BPFTOOL_REF}" \
        https://github.com/libbpf/bpftool.git /tmp/bpftool; \
    make -C /tmp/bpftool/src -j"$(nproc)"; \
    make -C /tmp/bpftool/src install prefix=/usr/local; \
    rm -rf /tmp/bpftool; \
    /usr/local/sbin/bpftool version

# 3) Go
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o /tmp/go.tgz; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz

ENV GOPATH=/go \
    GOTOOLCHAIN=local \
    GOFLAGS=-buildvcs=false \
    CGO_ENABLED=0 \
    PATH=/usr/local/go/bin:/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 4) 셸 편의 설정
RUN cat > /root/.bashrc <<'EOF'
export PS1='\[\e[1;32m\]ebpf-lab\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
export PATH=/usr/local/go/bin:/go/bin:/usr/local/sbin:$PATH
alias ll='ls -alF'
alias progs='bpftool prog list'
alias maps='bpftool map list'
alias links='bpftool link list'
alias tracepipe='cat /sys/kernel/debug/tracing/trace_pipe'

if [ -t 1 ]; then
  echo "eBPF lab  |  kernel $(uname -r) $(uname -m)  |  go $(go version | awk '{print $3}')  |  $(bpftool version | head -1)"
  echo "  make check        환경 점검"
  echo "  make generate     bpf2go 로 .bpf.c -> .o + Go 바인딩 생성"
  echo "  make 01 ~ 06      예제 실행 (make list 로 목록)"
fi
EOF

WORKDIR /lab
CMD ["sleep", "infinity"]
