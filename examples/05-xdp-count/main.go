// 05. XDP : 인터페이스로 들어오는 패킷을 프로토콜별로 집계
//
//	make 05
//	# 다른 터미널: make sh 후 ping -c3 1.1.1.1 / wget -qO- http://example.com
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type proto_stat xdp xdp.bpf.c -- -I../../include -Wall

const (
	slotARP   = 256
	slotIPv6  = 257
	slotOther = 258
	slotMax   = 259
)

func slotName(slot uint32) string {
	switch slot {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 132:
		return "SCTP"
	case slotARP:
		return "ARP"
	case slotIPv6:
		return "IPv6"
	case slotOther:
		return "기타 L3"
	default:
		return fmt.Sprintf("IP proto %d", slot)
	}
}

func main() {
	ifname := flag.String("iface", "eth0", "XDP 를 붙일 네트워크 인터페이스")
	native := flag.Bool("native", false, "native(드라이버) XDP 모드 강제. veth 에서는 보통 실패한다")
	flag.Parse()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("인터페이스 %q 를 찾을 수 없다: %v", *ifname, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs xdpObjects
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 오브젝트 로드 실패: %v", err)
	}
	defer objs.Close()

	mode := link.XDPGenericMode // SKB 모드: veth 등 어디서나 동작
	if *native {
		mode = link.XDPDriverMode
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCount,
		Interface: iface.Index,
		Flags:     mode,
	})
	if err != nil {
		log.Fatalf("XDP 부착 실패 (%s): %v", *ifname, err)
	}
	defer l.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("XDP 프로그램을 %s (mode=%v) 에 부착했다. 1초마다 출력, Ctrl-C 로 종료.\n", *ifname, mode)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-stop:
			fmt.Println("\n종료 (XDP 프로그램 detach).")
			return
		case <-tick.C:
			lines := 0
			var buf []string
			for slot := uint32(0); slot < slotMax; slot++ {
				var perCPU []xdpProtoStat
				if err := objs.ProtoStats.Lookup(slot, &perCPU); err != nil {
					continue
				}
				var pkts, bytes uint64
				for _, s := range perCPU {
					pkts += s.Packets
					bytes += s.Bytes
				}
				if pkts == 0 {
					continue
				}
				buf = append(buf, fmt.Sprintf("  %-12s %8d pkts %10d bytes", slotName(slot), pkts, bytes))
				lines++
			}
			if lines == 0 {
				continue
			}
			fmt.Printf("\n[%s] %s 수신 누적\n", time.Now().Format("15:04:05"), *ifname)
			for _, s := range buf {
				fmt.Println(s)
			}
		}
	}
}
