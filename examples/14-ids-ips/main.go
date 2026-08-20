// 14. IDS/IPS 게임 - 심판
//
// TC ingress 에서 UDP 페이로드의 악성 시그니처("EVIL")를 검사한다.
//   -mode ids : 탐지만 (경보 + 통과)
//   -mode ips : 차단 (경보 + 드롭)
// 시그니처 매칭/모드 처리(ids.bpf.c 의 TODO)는 네가 채운다.
//
//	make 14 ARGS="-iface lo -mode ids"
//	make 14 ARGS="-iface lo -mode ips"
//	# 공격:  echo 'payload-with-EVIL' | nc -u -w1 127.0.0.1 9999
//	# 자동 채점:  make 14-check
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type alert -type iconfig ids ids.bpf.c -- -I../../include -Wall

const (
	modeIDS = 0
	modeIPS = 1
)

func main() {
	ifname := flag.String("iface", "lo", "인터페이스")
	mode := flag.String("mode", "ids", "ids(탐지) | ips(차단)")
	flag.Parse()

	var m uint32 = modeIDS
	if *mode == "ips" {
		m = modeIPS
	}

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("인터페이스 %q: %v", *ifname, err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs idsObjects
	if err := loadIdsObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 로드 실패: %v", err)
	}
	defer objs.Close()

	if err := objs.IconfigMap.Put(uint32(0), &idsIconfig{Mode: m}); err != nil {
		log.Fatalf("config 주입: %v", err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IdsIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("TCX ingress 부착: %v", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.Ialerts)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() { <-stop; rd.Close() }()

	fmt.Printf("🛰️  IDS/IPS 엔진 부착 (%s, mode=%s, 시그니처=\"EVIL\").\n", *ifname, *mode)
	fmt.Println("   공격:  echo 'x-EVIL-x' | nc -u -w1 127.0.0.1 9999")
	fmt.Println("   Ctrl-C 로 종료.\n")

	go func() {
		var a idsAlert
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &a) == nil {
				verb := "탐지(통과)"
				if a.Blocked == 1 {
					verb = "차단(드롭)"
				}
				fmt.Printf("  🚨 시그니처 매치! %s -> :%d  [%s]\n", ipv4(a.Saddr), a.Dport, verb)
			}
		}
	}()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			seen, _ := sum(&objs, 0)
			hit, _ := sum(&objs, 1)
			blk, _ := sum(&objs, 2)
			fmt.Printf("\n\n종료. 검사 UDP %d, 시그니처 매치 %d, 차단 %d.\n", seen, hit, blk)
			if hit == 0 {
				fmt.Println("매치가 0이면 ids.bpf.c 의 TODO 를 안 채운 것이다.")
			}
			return
		case <-tick.C:
			seen, _ := sum(&objs, 0)
			hit, _ := sum(&objs, 1)
			blk, _ := sum(&objs, 2)
			mark := ""
			if hit > 0 {
				mark = "  🛰️ 침입 탐지 중"
			}
			fmt.Printf("\r[검사 UDP: %d]  [매치: %d]  [차단: %d]%s ", seen, hit, blk, mark)
		}
	}
}

func sum(objs *idsObjects, i uint32) (uint64, error) {
	var perCPU []uint64
	if err := objs.Istats.Lookup(i, &perCPU); err != nil {
		return 0, err
	}
	var t uint64
	for _, v := range perCPU {
		t += v
	}
	return t, nil
}

func ipv4(a uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], a)
	return net.IP(b[:]).String()
}
