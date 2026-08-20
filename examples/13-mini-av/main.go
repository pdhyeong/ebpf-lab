// 13. 미니 백신 - 심판
//
// lsm/file_open 훅으로 ".virus" 시그니처가 든 파일 열기를 격리(차단)한다.
// 시그니처 매칭 로직(av.bpf.c 의 TODO)은 네가 채운다.
//
//	# 터미널 A: 백신 가동
//	make 13
//	# 터미널 B: 감염 파일 접근 시도
//	make sh
//	  echo bad > /tmp/sample.virus.txt
//	  cat /tmp/sample.virus.txt      # 채우기 전: 읽힘 / 채운 뒤: Permission denied
//
// 자동 채점:  make 13-check
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH av av.bpf.c -- -I../../include -Wall

func main() {
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs avObjects
	if err := loadAvObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 로드 실패: %v", err)
	}
	defer objs.Close()

	l, err := link.AttachLSM(link.LSMOptions{Program: objs.AvScan})
	if err != nil {
		log.Fatalf("LSM 부착 실패: %v", err)
	}
	defer l.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Println("🦠 미니 백신 가동 (lsm/file_open, 시그니처=\".virus\").")
	fmt.Println("   시험:  echo bad > /tmp/sample.virus.txt && cat /tmp/sample.virus.txt")
	fmt.Println("   TODO 를 채우면 감염 파일 열기가 차단된다. Ctrl-C 로 종료.\n")

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			checked, _ := stat(&objs, 0)
			blocked, _ := stat(&objs, 1)
			fmt.Printf("\n\n종료. 검사한 open %d, 격리 %d.\n", checked, blocked)
			if blocked == 0 {
				fmt.Println("격리가 0이면 av.bpf.c 의 TODO 를 안 채운 것이다.")
			}
			return
		case <-tick.C:
			checked, _ := stat(&objs, 0)
			blocked, _ := stat(&objs, 1)
			mark := ""
			if blocked > 0 {
				mark = "  🦠 감염 파일 격리 중"
			}
			fmt.Printf("\r[검사한 open: %d]  [격리: %d]%s ", checked, blocked, mark)
		}
	}
}

func stat(objs *avObjects, i uint32) (uint64, error) {
	var v uint64
	err := objs.Avstats.Lookup(i, &v)
	return v, err
}
