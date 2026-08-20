// 08. TC 패킷 변조 : loopback 안에서 내 패킷을 실제로 고쳐 내보낸다
//
//	# TCP 목적지 포트 8080 -> 9090 으로 몰래 바꾸기 (DNAT)
//	make 08 ARGS="-iface lo -action dnat -match 8080 -to 9090"
//	# 그리고 다른 터미널에서:
//	#   서버:  make sh -> nc -lk -p 9090
//	#   접속:  make sh -> nc 127.0.0.1 8080   (8080 을 쳤는데 9090 서버에 붙는다!)
//
//	make 08 ARGS="-iface lo -action ttl  -ttl 42"    # 모든 IP 패킷 TTL=42
//	make 08 ARGS="-iface lo -action dscp -dscp 46"   # DSCP 46(EF) 마킹
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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type config mangle mangle.bpf.c -- -I../../include -Wall

const (
	actOff  = 0
	actTTL  = 1
	actDSCP = 2
	actDNAT = 3
)

func main() {
	ifname := flag.String("iface", "lo", "변조를 걸 인터페이스")
	action := flag.String("action", "dnat", "ttl | dscp | dnat")
	ttl := flag.Int("ttl", 42, "ttl 액션: 새 TTL 값")
	dscp := flag.Int("dscp", 46, "dscp 액션: 새 DSCP (0~63)")
	match := flag.Int("match", 8080, "dnat 액션: 이 목적지 포트를")
	to := flag.Int("to", 9090, "dnat 액션: 이 포트로 바꾼다")
	flag.Parse()

	var act uint32
	switch *action {
	case "ttl":
		act = actTTL
	case "dscp":
		act = actDSCP
	case "dnat":
		act = actDNAT
	default:
		log.Fatalf("모르는 action: %s (ttl|dscp|dnat)", *action)
	}

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("인터페이스 %q: %v", *ifname, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs mangleObjects
	if err := loadMangleObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 로드 실패: %v", err)
	}
	defer objs.Close()

	cfg := mangleConfig{
		Action:    act,
		Ttl:       uint8(*ttl),
		Dscp:      uint8(*dscp),
		MatchPort: uint16(*match),
		NewPort:   uint16(*to),
	}
	if err := objs.ConfigMap.Put(uint32(0), &cfg); err != nil {
		log.Fatalf("config 주입: %v", err)
	}

	// egress 에 붙는다. 이 패킷들은 "나가는" 패킷이고, TC egress 는 skb 가
	// 이미 완성된 상태라 store_bytes 로 안전하게 고칠 수 있다.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.MangleEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("TCX egress 부착 실패: %v", err)
	}
	defer l.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("🔧 %s egress 에 변조기 부착: ", *ifname)
	switch act {
	case actTTL:
		fmt.Printf("모든 IPv4 패킷의 TTL -> %d\n", *ttl)
	case actDSCP:
		fmt.Printf("모든 IPv4 패킷의 DSCP -> %d\n", *dscp)
	case actDNAT:
		fmt.Printf("TCP 목적지 포트 %d -> %d (DNAT)\n", *match, *to)
	}
	fmt.Println("Ctrl-C 로 종료 (종료하면 변조도 즉시 멈춘다).")

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			n, _ := sumRewrites(&objs)
			fmt.Printf("\n종료. 총 %d개 패킷을 변조했다.\n", n)
			return
		case <-tick.C:
			n, _ := sumRewrites(&objs)
			fmt.Printf("\r변조한 패킷 수: %d ", n)
		}
	}
}

func sumRewrites(objs *mangleObjects) (uint64, error) {
	var perCPU []uint64
	if err := objs.Rewrites.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var t uint64
	for _, v := range perCPU {
		t += v
	}
	return t, nil
}
