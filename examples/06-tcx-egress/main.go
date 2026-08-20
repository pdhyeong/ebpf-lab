// 06. TCX : ingress/egress 양방향 트래픽 집계 (커널 6.6+)
//
//	make 06
//	# 다른 터미널: make sh 후 ping / wget 으로 트래픽 발생
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type dir_stat tcx tcx.bpf.c -- -I../../include -Wall

const (
	dirIngress = 0
	dirEgress  = 1
)

func main() {
	ifname := flag.String("iface", "eth0", "TCX 를 붙일 인터페이스")
	flag.Parse()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("인터페이스 %q: %v", *ifname, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs tcxObjects
	if err := loadTcxObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 오브젝트 로드 실패: %v", err)
	}
	defer objs.Close()

	// TCX 는 qdisc(clsact) 를 만들 필요가 없다. bpf_link 하나로 끝.
	// 예전 방식(tc filter) 대비 detach 도 확실하다 -- 프로세스가 죽으면 자동 해제.
	ig, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcxIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("TCX ingress 부착 실패 (커널 6.6+ 필요): %v", err)
	}
	defer ig.Close()

	eg, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcxEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("TCX egress 부착 실패: %v", err)
	}
	defer eg.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("TCX ingress/egress 를 %s 에 부착했다. Ctrl-C 로 종료.\n", *ifname)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	var prev [2]tcxDirStat
	for {
		select {
		case <-stop:
			fmt.Println("\n종료.")
			return
		case <-tick.C:
			in, err1 := read(&objs, dirIngress)
			out, err2 := read(&objs, dirEgress)
			if err1 != nil || err2 != nil {
				log.Printf("map read: %v %v", err1, err2)
				continue
			}
			fmt.Printf("\n[%s] %s\n", time.Now().Format("15:04:05"), *ifname)
			fmt.Printf("%-8s %10s %12s %8s %8s %8s %12s\n",
				"DIR", "PKTS", "BYTES", "TCP", "UDP", "ICMP", "BPS(1s)")
			show("ingress", in, prev[0])
			show("egress", out, prev[1])
			prev[0], prev[1] = in, out
		}
	}
}

func show(name string, cur, prev tcxDirStat) {
	fmt.Printf("%-8s %10d %12d %8d %8d %8d %12d\n",
		name, cur.Packets, cur.Bytes, cur.Tcp, cur.Udp, cur.Icmp, cur.Bytes-prev.Bytes)
}

// PERCPU 맵은 CPU 별 값 배열로 돌아오므로 직접 합산한다.
func read(objs *tcxObjects, dir uint32) (tcxDirStat, error) {
	var perCPU []tcxDirStat
	if err := objs.DirStats.Lookup(dir, &perCPU); err != nil {
		return tcxDirStat{}, err
	}
	var t tcxDirStat
	for _, s := range perCPU {
		t.Packets += s.Packets
		t.Bytes += s.Bytes
		t.Tcp += s.Tcp
		t.Udp += s.Udp
		t.Icmp += s.Icmp
	}
	return t, nil
}
