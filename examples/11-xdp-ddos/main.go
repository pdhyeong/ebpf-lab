// 11. XDP DDoS 방어 게임 - 심판
//
// XDP 프로그램을 인터페이스에 붙여 SYN flood 를 초당 임계값 기준으로 차단한다.
// 탐지·차단 로직(ddos.bpf.c 의 TODO)은 네가 채운다.
//
//	make 11 ARGS="-iface lo -rate 50"    # 초당 SYN 50개 넘는 출발지 차단
//	# 자동 채점:  make 11-check
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type dconfig ddos ddos.bpf.c -- -I../../include -Wall

func main() {
	ifname := flag.String("iface", "lo", "XDP 를 붙일 인터페이스")
	rate := flag.Int("rate", 50, "출발지별 초당 SYN 임계값 (넘으면 차단)")
	flag.Parse()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("인터페이스 %q: %v", *ifname, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs ddosObjects
	if err := loadDdosObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 로드 실패: %v", err)
	}
	defer objs.Close()

	cfg := ddosDconfig{SynPerSec: uint32(*rate)}
	if err := objs.ConfigMap.Put(uint32(0), &cfg); err != nil {
		log.Fatalf("config 주입: %v", err)
	}

	// veth/lo 는 native XDP 가 없으므로 generic(SKB) 모드로 붙인다.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DdosFilter,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("XDP 부착 실패: %v", err)
	}
	defer l.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("🛡️  XDP DDoS 필터 부착 (%s, 임계값 %d SYN/s).\n", *ifname, *rate)
	fmt.Println("   공격 시뮬레이션:  make 11-check  (또는 hping3 스타일 부하)")
	fmt.Println("   Ctrl-C 로 종료.\n")

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastSeen, lastDrop uint64
	for {
		select {
		case <-stop:
			seen, _ := sum(&objs, 0)
			drop, _ := sum(&objs, 1)
			fmt.Printf("\n\n종료. 검사한 SYN %d, 차단 %d.\n", seen, drop)
			if drop == 0 {
				fmt.Println("차단이 0이면 ddos.bpf.c 의 TODO 를 아직 안 채운 것이다.")
			}
			return
		case <-tick.C:
			seen, _ := sum(&objs, 0)
			drop, _ := sum(&objs, 1)
			mark := ""
			if drop > lastDrop {
				mark = "  🛡️ 공격 차단 중"
			}
			fmt.Printf("\r[SYN 검사: %d (+%d/s)]  [차단: %d (+%d/s)]%s ",
				seen, seen-lastSeen, drop, drop-lastDrop, mark)
			lastSeen, lastDrop = seen, drop
		}
	}
}

func sum(objs *ddosObjects, i uint32) (uint64, error) {
	var perCPU []uint64
	if err := objs.Xstats.Lookup(i, &perCPU); err != nil {
		return 0, err
	}
	var t uint64
	for _, v := range perCPU {
		t += v
	}
	return t, nil
}
