// 03. fentry/fexit : TCP 커넥트 추적 (Cilium 스타일 BTF 트레이싱)
//
//	make 03
//	# 다른 터미널: make sh 후 wget -qO- http://example.com
//	# victim 컨테이너가 3초마다 http 요청을 날리므로 가만히 둬도 이벤트가 찍힌다
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type event tcpconnect tcpconnect.bpf.c -- -I../../include -Wall

const (
	statCalls = iota
	statFailed
	statIPv6
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs tcpconnectObjects
	if err := loadTcpconnectObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 오브젝트 로드 실패 (fentry 미지원 커널이면 여기서 실패): %v", err)
	}
	defer objs.Close()

	// fentry/fexit 는 link.AttachTracing 으로 붙인다. kprobe 처럼 심볼 이름을
	// 따로 넘기지 않는다 -- 대상 함수가 프로그램의 BTF 에 이미 박혀 있다.
	fentry, err := link.AttachTracing(link.TracingOptions{Program: objs.TcpConnectEntry})
	if err != nil {
		log.Fatalf("fentry 부착 실패: %v", err)
	}
	defer fentry.Close()

	fexit, err := link.AttachTracing(link.TracingOptions{Program: objs.TcpConnectExit})
	if err != nil {
		log.Fatalf("fexit 부착 실패: %v", err)
	}
	defer fexit.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// 5초마다 통계 출력
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for range tick.C {
			calls, _ := sum(objs, statCalls)
			failed, _ := sum(objs, statFailed)
			v6, _ := sum(objs, statIPv6)
			fmt.Printf("  -- 누적: tcp_connect %d 건 (실패 %d, IPv6 %d)\n", calls, failed, v6)
		}
	}()

	go func() {
		<-stop
		rd.Close()
	}()

	fmt.Printf("fentry/tcp_connect + fexit/tcp_connect 부착 완료. Ctrl-C 로 종료.\n\n")
	fmt.Printf("%-8s %-16s %-22s -> %-22s\n", "PID", "COMM", "SRC", "DST")

	var ev tcpconnectEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("\n종료.")
				return
			}
			log.Printf("read: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decode: %v", err)
			continue
		}

		fmt.Printf("%-8d %-16s %-22s -> %-22s\n",
			ev.Tgid, cstr(ev.Comm[:]),
			net.JoinHostPort(ipv4(ev.Saddr), fmt.Sprint(ev.Sport)),
			net.JoinHostPort(ipv4(ev.Daddr), fmt.Sprint(ev.Dport)),
		)
	}
}

// ipv4 는 네트워크 바이트 오더 __be32 를 점표기 문자열로 바꾼다.
func ipv4(addr uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], addr)
	return net.IP(b[:]).String()
}

func sum(objs tcpconnectObjects, slot uint32) (uint64, error) {
	var perCPU []uint64
	if err := objs.Stats.Lookup(slot, &perCPU); err != nil {
		return 0, err
	}
	var t uint64
	for _, v := range perCPU {
		t += v
	}
	return t, nil
}

func cstr(b []uint8) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
