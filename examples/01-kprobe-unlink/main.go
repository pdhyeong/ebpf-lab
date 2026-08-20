// 01. kprobe + ringbuf : 파일 삭제(unlink) 실시간 추적
//
//	make 01
//	# 다른 터미널에서: make sh 후 touch /tmp/x && rm /tmp/x
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type event unlink unlink.bpf.c -- -I../../include -Wall

func main() {
	// 오래된 커널을 위한 memlock 제한 해제. 5.11+ 는 memcg 로 계산하므로 사실상 no-op.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	// 1) 커널에 오브젝트 로드 (맵 생성 + 프로그램 검증)
	var objs unlinkObjects
	if err := loadUnlinkObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 오브젝트 로드 실패: %v", err)
	}
	defer objs.Close()

	// 2) do_unlinkat 심볼에 kprobe 부착
	kp, err := link.Kprobe("do_unlinkat", objs.DoUnlinkat, nil)
	if err != nil {
		log.Fatalf("kprobe 부착 실패: %v", err)
	}
	defer kp.Close()

	// 3) 링버퍼 리더 오픈
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

	fmt.Printf("kprobe/do_unlinkat 부착 완료. Ctrl-C 로 종료.\n\n")
	fmt.Printf("%-8s %-8s %-16s %s\n", "PID", "TID", "COMM", "FILENAME")

	var ev unlinkEvent
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

		fmt.Printf("%-8d %-8d %-16s %s\n",
			ev.Tgid, ev.Pid, cstr(ev.Comm[:]), cstr(ev.Filename[:]))
	}
}

// cstr 은 NUL 로 끝나는 고정 길이 바이트 배열을 Go 문자열로 바꾼다.
func cstr(b []uint8) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
