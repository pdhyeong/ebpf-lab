// 07. 실무형 런타임 감시 에이전트
//
// 여러 프로브(exec / tcp connect / unlink)를 하나의 오브젝트로 로드하고,
// 커널에서 필터링하고, cgroup id 로 컨테이너에 귀속시키고, 유실을 세고,
// JSON 로그와 Prometheus 메트릭으로 내보낸다.
//
//	make 07
//	make 07 ARGS="-json"
//	make 07 ARGS="-metrics :9101"                 # curl localhost:9101/metrics
//	make 07 ARGS="-container ebpf-victim"         # 특정 컨테이너만
//	make 07 ARGS="-pin"                           # bpftool 로 맵을 들여다볼 수 있게 pin
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type event -type config audit audit.bpf.c -- -I../../include -Wall

const (
	kindExec    = 1
	kindConnect = 2
	kindUnlink  = 3
)

const (
	statExec = iota
	statConnect
	statUnlink
	statDropped
	statFiltered
	statMax
)

const pinDir = "/sys/fs/bpf/ebpf-audit"

func kindName(k uint8) string {
	switch k {
	case kindExec:
		return "EXEC"
	case kindConnect:
		return "CONNECT"
	case kindUnlink:
		return "UNLINK"
	}
	return "?"
}

// logLine 은 -json 모드에서 한 줄로 출력되는 스키마다.
// 실무에서는 이 스키마가 곧 계약이므로 필드 이름을 함부로 바꾸면 안 된다.
type logLine struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	CgroupID  uint64    `json:"cgroup_id"`
	Container string    `json:"container,omitempty"`
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	UID       uint32    `json:"uid"`
	Comm      string    `json:"comm"`
	Path      string    `json:"path,omitempty"`
	Dest      string    `json:"dest,omitempty"`
}

func main() {
	var (
		jsonOut    = flag.Bool("json", false, "JSON Lines 로 출력")
		metricsBnd = flag.String("metrics", "", "Prometheus 메트릭 리스닝 주소 (예: :9101)")
		container  = flag.String("container", "", "이 컨테이너만 추적 (이름 또는 ID prefix)")
		cgroupPath = flag.String("cgroup", "", "이 cgroup 경로만 추적 (-container 보다 우선)")
		wantExec   = flag.Bool("exec", true, "execve 추적")
		wantConn   = flag.Bool("connect", true, "tcp connect 추적")
		wantUnlink = flag.Bool("unlink", true, "unlink 추적")
		doPin      = flag.Bool("pin", false, pinDir+" 에 맵을 pin (bpftool 로 조회 가능)")
		cgroupRoot = flag.String("cgroup-root", "/sys/fs/cgroup", "cgroup v2 루트")
		dockerSock = flag.String("docker-sock", "/var/run/docker.sock", "컨테이너 이름 조회용 소켓 (없으면 ID 만 표시)")
	)
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	// ---- 컨테이너 해석기: cgroup id(inode) -> 컨테이너 ----
	res := newResolver(*cgroupRoot, *dockerSock)
	if err := res.refresh(); err != nil {
		log.Printf("경고: cgroup 스캔 실패 (%v). 컨테이너 이름 없이 진행한다.", err)
	}

	// ---- 필터 대상 cgroup 결정 ----
	var targetCgroupID uint64
	switch {
	case *cgroupPath != "":
		id, err := cgroupIDOf(*cgroupPath)
		if err != nil {
			log.Fatalf("cgroup %q: %v", *cgroupPath, err)
		}
		targetCgroupID = id
	case *container != "":
		c, ok := res.findByName(*container)
		if !ok {
			log.Fatalf("컨테이너 %q 를 cgroup 트리에서 찾지 못했다. "+
				"compose 에 'cgroup: host' 와 /sys/fs/cgroup 마운트가 있는지 확인.", *container)
		}
		targetCgroupID = c.CgroupID
		log.Printf("대상: %s (cgroup_id=%d, %s)", c.Display(), c.CgroupID, c.CgroupPath)
	}

	// ---- BPF 로드 (verifier 실패 시 로그 전문을 찍는다) ----
	var objs auditObjects
	if err := loadAuditObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// %+v 로 출력해야 verifier 로그가 잘리지 않는다. 실무 디버깅의 시작점.
			log.Fatalf("verifier 거부:\n%+v", ve)
		}
		log.Fatalf("BPF 오브젝트 로드 실패: %v", err)
	}
	defer objs.Close()

	// ---- 런타임 설정을 맵에 주입 (재컴파일 없이 동작을 바꾼다) ----
	cfg := auditConfig{
		CgroupId:    targetCgroupID,
		SelfPid:     uint32(os.Getpid()),
		WantExec:    b2u8(*wantExec),
		WantConnect: b2u8(*wantConn),
		WantUnlink:  b2u8(*wantUnlink),
	}
	if err := objs.ConfigMap.Put(uint32(0), &cfg); err != nil {
		log.Fatalf("config 맵 주입 실패: %v", err)
	}

	if *doPin {
		if err := pinMaps(&objs); err != nil {
			log.Printf("경고: pin 실패: %v", err)
		} else {
			log.Printf("맵을 %s 에 pin 했다. 다른 터미널에서: bpftool map dump pinned %s/stats", pinDir, pinDir)
			defer unpinMaps(&objs)
		}
	}

	// ---- 어태치 ----
	var links []link.Link
	attach := func(name string, l link.Link, err error) {
		if err != nil {
			log.Fatalf("%s 부착 실패: %v", name, err)
		}
		links = append(links, l)
	}
	if *wantExec {
		l, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
		attach("tracepoint/sys_enter_execve", l, err)
	}
	if *wantConn {
		l, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceTcpConnect})
		attach("fentry/tcp_connect", l, err)
	}
	if *wantUnlink {
		l, err := link.Kprobe("do_unlinkat", objs.TraceUnlinkat, nil)
		attach("kprobe/do_unlinkat", l, err)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// ---- 메트릭 서버 ----
	if *metricsBnd != "" {
		go serveMetrics(*metricsBnd, &objs, res)
		log.Printf("Prometheus 메트릭: http://localhost%s/metrics", *metricsBnd)
	}

	// ---- 링버퍼 ----
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		rd.Close()
	}()

	// cgroup 트리는 컨테이너가 뜨고 죽으면 바뀌므로 주기적으로 다시 읽는다.
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			_ = res.refresh()
		}
	}()

	// bpf_ktime_get_ns 는 CLOCK_MONOTONIC 기준이다. 벽시계로 바꾸려면
	// (현재 벽시계 - 현재 monotonic) 오프셋을 한 번 구해서 더한다.
	wallOffset, err := monotonicToWallOffset()
	if err != nil {
		log.Printf("경고: 시각 보정 실패 (%v). 상대 시간으로 표시한다.", err)
	}

	enc := json.NewEncoder(os.Stdout)
	if !*jsonOut {
		fmt.Printf("\n프로브 %d 개 부착 완료", len(links))
		if targetCgroupID != 0 {
			fmt.Printf(" (cgroup_id=%d 로 커널 필터링)", targetCgroupID)
		}
		fmt.Printf(". Ctrl-C 로 종료.\n\n")
		fmt.Printf("%-12s %-8s %-18s %-8s %-8s %-6s %-16s %s\n",
			"TIME", "KIND", "CONTAINER", "PID", "PPID", "UID", "COMM", "DETAIL")
	}

	var ev auditEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				printFinalStats(&objs)
				return
			}
			log.Printf("read: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decode: %v", err)
			continue
		}

		line := logLine{
			Time:     wallOffset.Add(time.Duration(ev.Ts)),
			Kind:     kindName(ev.Kind),
			CgroupID: ev.CgroupId,
			PID:      ev.Tgid,
			PPID:     ev.Ppid,
			UID:      ev.Uid,
			Comm:     cstr(ev.Comm[:]),
		}
		if c, ok := res.lookup(ev.CgroupId); ok {
			line.Container = c.Display()
		}
		switch ev.Kind {
		case kindConnect:
			line.Dest = net.JoinHostPort(ipv4(ev.Daddr), fmt.Sprint(ev.Dport))
		default:
			line.Path = cstr(ev.Path[:])
		}

		if *jsonOut {
			_ = enc.Encode(line)
			continue
		}

		detail := line.Path
		if detail == "" {
			detail = line.Dest
		}
		cname := line.Container
		if cname == "" {
			cname = "-"
		}
		fmt.Printf("%-12s %-8s %-18s %-8d %-8d %-6d %-16s %s\n",
			line.Time.Format("15:04:05.000"), line.Kind, truncate(cname, 18),
			line.PID, line.PPID, line.UID, line.Comm, detail)
	}
}

func printFinalStats(objs *auditObjects) {
	s, err := readStats(objs)
	if err != nil {
		fmt.Println("\n종료.")
		return
	}
	fmt.Printf("\n종료. exec=%d connect=%d unlink=%d 커널필터=%d \033[31m유실=%d\033[0m\n",
		s[statExec], s[statConnect], s[statUnlink], s[statFiltered], s[statDropped])
	if s[statDropped] > 0 {
		fmt.Println("유실이 있었다면 링버퍼 크기를 늘리거나 커널 필터를 좁혀야 한다.")
	}
}

// readStats 는 PERCPU_ARRAY 를 슬롯별로 합산한다.
func readStats(objs *auditObjects) ([statMax]uint64, error) {
	var out [statMax]uint64
	for i := uint32(0); i < statMax; i++ {
		var perCPU []uint64
		if err := objs.Stats.Lookup(i, &perCPU); err != nil {
			return out, err
		}
		for _, v := range perCPU {
			out[i] += v
		}
	}
	return out, nil
}

func pinMaps(objs *auditObjects) error {
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return err
	}
	for name, m := range map[string]*ebpf.Map{
		"stats":  objs.Stats,
		"config": objs.ConfigMap,
		"events": objs.Events,
	} {
		p := filepath.Join(pinDir, name)
		_ = os.Remove(p)
		if err := m.Pin(p); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func unpinMaps(objs *auditObjects) {
	for _, m := range []*ebpf.Map{objs.Stats, objs.ConfigMap, objs.Events} {
		_ = m.Unpin()
	}
	_ = os.Remove(pinDir)
}

// monotonicToWallOffset 은 monotonic ns 값에 더하면 벽시계가 되는 기준점을 만든다.
func monotonicToWallOffset() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Now(), err
	}
	return time.Now().Add(-time.Duration(ts.Nano())), nil
}

func ipv4(addr uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], addr)
	return net.IP(b[:]).String()
}

func cstr(b []uint8) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.ToValidUTF8(string(b), "")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
