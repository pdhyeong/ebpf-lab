// 10. LSM 보안 게임 - 심판
//
// LSM 훅을 커널에 붙여 "malware" 로 끝나는 실행 파일을 차단한다.
// 차단 조건(guard.bpf.c 의 TODO)은 네가 채운다.
//
//	# 터미널 A: 가드 부착
//	make 10
//	# 터미널 B: 공격 시도
//	make sh
//	  cp /bin/echo /tmp/malware
//	  /tmp/malware        # 채우기 전: 실행됨(뚫림) / 채운 뒤: Operation not permitted
//
// 자동 채점:  make 10-check
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH guard guard.bpf.c -- -I../../include -Wall

func main() {
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs guardObjects
	if err := loadGuardObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 로드 실패: %v", err)
	}
	defer objs.Close()

	// LSM 프로그램은 link.AttachLSM 으로 붙인다. 붙는 순간부터 반환값이
	// 커널 결정에 반영된다 (-EPERM = 거부).
	l, err := link.AttachLSM(link.LSMOptions{Program: objs.ExecGuard})
	if err != nil {
		log.Fatalf("LSM 부착 실패 (CONFIG_LSM 에 bpf 필요): %v", err)
	}
	defer l.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Println("🛡️  LSM 실행 가드 부착됨 (bprm_check_security).")
	fmt.Println("   다른 터미널에서 시험:")
	fmt.Println("     cp /bin/echo /tmp/malware && /tmp/malware")
	fmt.Println("   차단 조건을 안 채웠으면 그냥 실행되고, 채웠으면 거부된다.")
	fmt.Println("   Ctrl-C 로 종료 (종료하면 가드도 풀린다).\n")

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			checked, _ := stat(&objs, 0)
			blocked, _ := stat(&objs, 1)
			fmt.Printf("\n\n종료. 검사한 exec %d개, 차단 %d개.\n", checked, blocked)
			if blocked == 0 {
				fmt.Println("차단이 0이면 guard.bpf.c 의 TODO 를 아직 안 채운 것이다.")
			}
			return
		case <-tick.C:
			checked, _ := stat(&objs, 0)
			blocked, _ := stat(&objs, 1)
			mark := ""
			if blocked > 0 {
				mark = "  🛡️ 차단 작동 중"
			}
			fmt.Printf("\r[검사한 exec: %d]  [차단: %d]%s ", checked, blocked, mark)
		}
	}
}

func stat(objs *guardObjects, i uint32) (uint64, error) {
	var v uint64
	err := objs.Gstats.Lookup(i, &v)
	return v, err
}
