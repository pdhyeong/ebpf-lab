// 09. 변조 vs 탐지 게임 - 심판(referee)
//
// 이 프로그램은 "🔵 Blue 탐지기"를 커널에 붙이고, 몇 개를 잡았는지 점수를 센다.
// 탐지 로직(detect.bpf.c)은 네가 직접 채워야 한다. 빈칸이면 아무것도 못 잡는다.
//
//	# 터미널 A: 심판 + 탐지기
//	make 09
//	# 터미널 B: 🔴 Red 공격 (08번 변조기를 무기로 쓴다)
//	make 08 ARGS="-iface lo -action ttl -ttl 42"
//	# 터미널 C: 트래픽 발생
//	make sh -> ping -c5 127.0.0.1
//
// detect.bpf.c 의 TODO 를 채우기 전:  [잡은 공격: 0]  <- 실패
// TTL 검사를 채운 뒤:                [잡은 공격: 5]  🚨  <- 클리어
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type alert -type dconfig detect detect.bpf.c -- -I../../include -Wall

const (
	alertTTL    = 1
	alertBadHdr = 2
	alertPort   = 3
)

const (
	statSeen = iota
	statTTL
	statBadHdr
	statPort
	statMax
)

func alertName(k uint8) string {
	switch k {
	case alertTTL:
		return "🚨 TTL 변조"
	case alertBadHdr:
		return "🚨 헤더 조작"
	case alertPort:
		return "🚨 포트 리다이렉트"
	}
	return "?"
}

func main() {
	ifname := flag.String("iface", "lo", "탐지기를 붙일 인터페이스")
	watchPort := flag.Int("watch", 0, "포트 감시: 이 포트로 오던 트래픽이 (0=끔)")
	allowPort := flag.Int("allow", 0, "포트 감시: 이 포트만 정상")
	checkTTL := flag.Bool("ttl", true, "TTL 불변식 검사 on/off")
	flag.Parse()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("인터페이스 %q: %v", *ifname, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs detectObjects
	if err := loadDetectObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 로드 실패: %v", err)
	}
	defer objs.Close()

	cfg := detectDconfig{
		WatchPort: uint16(*watchPort),
		AllowPort: uint16(*allowPort),
		CheckTtl:  b2u8(*checkTTL),
	}
	if err := objs.DconfigMap.Put(uint32(0), &cfg); err != nil {
		log.Fatalf("config 주입: %v", err)
	}

	// 탐지기는 ingress 에 붙는다. loopback 은 egress 로 나간(=Red 가 변조한)
	// 패킷이 그대로 ingress 로 돌아오므로 여기서 검사한다.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.DetectIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("TCX ingress 부착 실패: %v", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.Alerts)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() { <-stop; rd.Close() }()

	fmt.Printf("🔵 Blue 탐지기를 %s ingress 에 부착. 🔴 Red 공격을 기다린다...\n\n", *ifname)
	fmt.Println("힌트: 아무것도 안 잡히면 detect.bpf.c 의 TODO 를 아직 안 채운 것이다.")
	fmt.Println("      다른 터미널에서 Red 공격을 실행하라:")
	fmt.Println("        make 08 ARGS=\"-iface lo -action ttl -ttl 42\"")
	fmt.Println("      그리고 트래픽:  ping -c5 127.0.0.1\n")

	// 실시간 경보 스트림
	go func() {
		var a detectAlert
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &a); err != nil {
				continue
			}
			detail := ""
			switch a.Kind {
			case alertTTL:
				detail = fmt.Sprintf("TTL=%d (정상은 %d)", a.Got, a.Expected)
			case alertBadHdr:
				detail = fmt.Sprintf("IHL/version 바이트=0x%02x", a.Got)
			case alertPort:
				detail = fmt.Sprintf("목적지 포트=%d", a.Dport)
			}
			fmt.Printf("  %s  %s -> %s  %s\n",
				alertName(a.Kind), ipv4(a.Saddr), ipv4(a.Daddr), detail)
		}
	}()

	// 스코어보드
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			printScore(&objs)
			return
		case <-tick.C:
			s, _ := readStats(&objs)
			caught := s[statTTL] + s[statBadHdr] + s[statPort]
			mark := ""
			if caught > 0 {
				mark = "  ✅ 탐지 성공!"
			}
			fmt.Printf("\r[검사한 패킷: %d]  [잡은 공격: %d]%s ",
				s[statSeen], caught, mark)
		}
	}
}

func printScore(objs *detectObjects) {
	s, _ := readStats(objs)
	caught := s[statTTL] + s[statBadHdr] + s[statPort]
	fmt.Printf("\n\n=== 최종 점수 ===\n")
	fmt.Printf("  검사한 패킷 : %d\n", s[statSeen])
	fmt.Printf("  TTL 변조    : %d\n", s[statTTL])
	fmt.Printf("  헤더 조작   : %d\n", s[statBadHdr])
	fmt.Printf("  포트 변조   : %d\n", s[statPort])
	if caught == 0 {
		fmt.Printf("\n  ❌ 아무것도 못 잡았다. detect.bpf.c 의 TODO 를 채웠는지 확인하라.\n")
		fmt.Printf("     막히면 solution/detect.bpf.c 를 참고.\n")
	} else {
		fmt.Printf("\n  ✅ 공격 %d건 탐지! 훌륭하다.\n", caught)
	}
}

func readStats(objs *detectObjects) ([statMax]uint64, error) {
	var out [statMax]uint64
	for i := uint32(0); i < statMax; i++ {
		var perCPU []uint64
		if err := objs.Dstats.Lookup(i, &perCPU); err != nil {
			return out, err
		}
		for _, v := range perCPU {
			out[i] += v
		}
	}
	return out, nil
}

func ipv4(a uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], a)
	return net.IP(b[:]).String()
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
