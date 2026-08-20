// 02. tracepoint + 해시맵 집계 : 프로세스별 openat(2) 호출 순위
//
//	make 02
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type proc_key openat openat.bpf.c -- -I../../include -Wall

type row struct {
	tgid  uint32
	comm  string
	count uint64
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	var objs openatObjects
	if err := loadOpenatObjects(&objs, nil); err != nil {
		log.Fatalf("BPF 오브젝트 로드 실패: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		log.Fatalf("tracepoint 부착 실패: %v", err)
	}
	defer tp.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Println("tracepoint/syscalls/sys_enter_openat 부착 완료. 1초마다 집계 출력, Ctrl-C 로 종료.")

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-stop:
			fmt.Println("\n종료.")
			return
		case <-tick.C:
			rows, err := snapshot(&objs)
			if err != nil {
				log.Printf("map read: %v", err)
				continue
			}
			total, _ := readTotal(&objs)

			fmt.Printf("\n[%s] 누적 openat 호출 %d 건, 프로세스 %d 개\n",
				time.Now().Format("15:04:05"), total, len(rows))
			fmt.Printf("%-8s %-20s %10s\n", "PID", "COMM", "COUNT")
			for i, r := range rows {
				if i >= 10 {
					fmt.Printf("... (%d개 더)\n", len(rows)-10)
					break
				}
				fmt.Printf("%-8d %-20s %10d\n", r.tgid, r.comm, r.count)
			}
		}
	}
}

// snapshot 은 해시맵 전체를 순회해서 카운트 내림차순으로 정렬한다.
func snapshot(objs *openatObjects) ([]row, error) {
	var (
		key  openatProcKey
		val  uint64
		rows []row
	)
	iter := objs.Counts.Iterate()
	for iter.Next(&key, &val) {
		rows = append(rows, row{tgid: key.Tgid, comm: cstr(key.Comm[:]), count: val})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })
	return rows, nil
}

// readTotal 은 PERCPU 배열이므로 CPU 개수만큼의 값을 받아 직접 합산해야 한다.
func readTotal(objs *openatObjects) (uint64, error) {
	var perCPU []uint64
	if err := objs.Total.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}

func cstr(b []uint8) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
