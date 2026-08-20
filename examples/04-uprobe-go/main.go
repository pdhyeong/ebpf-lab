// 04. uprobe : 내가 만든 Go 프로그램의 함수를 트레이싱
//
//	make workload      # 타깃 빌드
//	make 04            # (타깃이 안 돌고 있으면 알아서 띄워준다)
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type event uprobe uprobe.bpf.c -- -I../../include -Wall

func main() {
	// 주의: /lab 은 macOS 바인드 마운트(virtiofs)라서 uprobe 를 붙일 수 없다
	// (perf_event_open 이 EIO). 타깃은 컨테이너 로컬 파일시스템에 둔다.
	binPath := flag.String("bin", "/opt/lab/bin/workload", "uprobe 를 붙일 실행 파일")
	symbol := flag.String("sym", "main.compute", "트레이싱할 심볼 이름")
	pid := flag.Int("pid", -1, "특정 PID 만 추적 (-1 이면 해당 바이너리의 모든 프로세스)")
	flag.Parse()

	if _, err := os.Stat(*binPath); err != nil {
		log.Fatalf("타깃 바이너리가 없다 (%s). 먼저 'make workload' 실행: %v", *binPath, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs uprobeObjects
	if err := loadUprobeObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 오브젝트 로드 실패: %v", err)
	}
	defer objs.Close()

	// 1) 실행 파일을 열어 ELF 심볼 테이블을 파싱한다.
	ex, err := link.OpenExecutable(*binPath)
	if err != nil {
		log.Fatalf("실행 파일 열기 실패: %v", err)
	}

	// 2) 심볼 오프셋에 uprobe 부착. PID 를 지정하면 그 프로세스만 걸린다.
	opts := &link.UprobeOptions{}
	if *pid > 0 {
		opts.PID = *pid
	}
	up, err := ex.Uprobe(*symbol, objs.UprobeCompute, opts)
	if err != nil {
		log.Fatalf("uprobe 부착 실패 (심볼 %q 가 스트립되지 않았는지 확인): %v", *symbol, err)
	}
	defer up.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		rd.Close()
	}()

	fmt.Printf("uprobe %s:%s 부착 완료. Ctrl-C 로 종료.\n\n", *binPath, *symbol)
	fmt.Printf("%-14s %-8s %-8s %-16s %s\n", "UPTIME(s)", "PID", "TID", "COMM", "ARG(n)")

	var ev uprobeEvent
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

		fmt.Printf("%-14.3f %-8d %-8d %-16s %d\n",
			time.Duration(ev.Ts).Seconds(), ev.Tgid, ev.Pid, cstr(ev.Comm[:]), ev.Arg)
	}
}

func cstr(b []uint8) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
