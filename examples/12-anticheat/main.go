// 12. 안티치트 게임 - 심판
//
// 게임 바이너리의 setHealth() 에 uprobe 를 붙여 체력 규칙 위반(치트)을 잡는다.
// 판정 로직(anticheat.bpf.c 의 TODO)은 네가 채운다.
//
//	# 타깃 게임 빌드
//	make game
//	# 터미널 A: 안티치트 부착
//	make 12
//	# 터미널 B: 치트 실행
//	/opt/lab/bin/game -cheat
//
// 자동 채점:  make 12-check
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type cheat_evt anticheat anticheat.bpf.c -- -I../../include -Wall

func main() {
	binPath := flag.String("bin", "/opt/lab/bin/game", "감시할 게임 바이너리")
	symbol := flag.String("sym", "main.setHealth", "감시할 함수")
	flag.Parse()

	if _, err := os.Stat(*binPath); err != nil {
		log.Fatalf("게임 바이너리가 없다 (%s). 먼저 'make game': %v", *binPath, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs anticheatObjects
	if err := loadAnticheatObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 로드 실패: %v", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(*binPath)
	if err != nil {
		log.Fatalf("실행 파일 열기: %v", err)
	}
	up, err := ex.Uprobe(*symbol, objs.CheckHealth, nil)
	if err != nil {
		log.Fatalf("uprobe 부착 실패 (심볼 스트립 여부 확인): %v", err)
	}
	defer up.Close()

	rd, err := ringbuf.NewReader(objs.Cheats)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() { <-stop; rd.Close() }()

	fmt.Printf("🕵️  안티치트 부착: %s:%s\n", *binPath, *symbol)
	fmt.Println("   정상 플레이는 조용하고, 치트(HP>100)는 잡힌다.")
	fmt.Println("   치트 실행:  /opt/lab/bin/game -cheat")
	fmt.Println("   Ctrl-C 로 종료.\n")

	go func() {
		var e anticheatCheatEvt
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e) == nil {
				fmt.Printf("  🚨 치트 탐지! pid=%d comm=%s  HP=%d (규칙: <=%d)\n",
					e.Pid, cstr(e.Comm[:]), e.Value, e.Limit)
			}
		}
	}()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			checked, _ := sum(&objs, 0)
			caught, _ := sum(&objs, 1)
			fmt.Printf("\n\n종료. 검사한 호출 %d, 치트 탐지 %d.\n", checked, caught)
			if caught == 0 {
				fmt.Println("탐지가 0이면 anticheat.bpf.c 의 TODO 를 안 채운 것이다.")
			}
			return
		case <-tick.C:
			checked, _ := sum(&objs, 0)
			caught, _ := sum(&objs, 1)
			mark := ""
			if caught > 0 {
				mark = "  🕵️ 치트 탐지 중"
			}
			fmt.Printf("\r[검사한 호출: %d]  [치트: %d]%s ", checked, caught, mark)
		}
	}
}

func sum(objs *anticheatObjects, i uint32) (uint64, error) {
	var perCPU []uint64
	if err := objs.Acstats.Lookup(i, &perCPU); err != nil {
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
