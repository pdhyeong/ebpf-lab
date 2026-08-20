package main

// Prometheus 노출.
//
// 의존성을 늘리지 않으려고 텍스트 포맷을 직접 만든다. 실무에서는
// prometheus/client_golang 을 쓰지만, 노출하는 값의 성격은 똑같다:
//
//	events_total{kind=...}  카운터  -- 실제로 올린 이벤트
//	dropped_total           카운터  -- 링버퍼가 꽉 차서 버린 이벤트 (SLO 의 핵심)
//	filtered_total          카운터  -- 커널에서 걸러낸 이벤트 (필터 효율 확인용)
//
// dropped 가 0 이 아니면 관측 데이터에 구멍이 있다는 뜻이다. 이 값을
// 노출하지 않는 관측 에이전트는 신뢰할 수 없다.

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func serveMetrics(addr string, objs *auditObjects, res *resolver) {
	mux := http.NewServeMux()

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s, err := readStats(objs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var b strings.Builder
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		b.WriteString("# HELP ebpf_audit_events_total 유저 공간으로 전달된 이벤트 수\n")
		b.WriteString("# TYPE ebpf_audit_events_total counter\n")
		fmt.Fprintf(&b, "ebpf_audit_events_total{kind=\"exec\"} %d\n", s[statExec])
		fmt.Fprintf(&b, "ebpf_audit_events_total{kind=\"connect\"} %d\n", s[statConnect])
		fmt.Fprintf(&b, "ebpf_audit_events_total{kind=\"unlink\"} %d\n", s[statUnlink])

		b.WriteString("# HELP ebpf_audit_dropped_total 링버퍼 포화로 유실된 이벤트 수\n")
		b.WriteString("# TYPE ebpf_audit_dropped_total counter\n")
		fmt.Fprintf(&b, "ebpf_audit_dropped_total %d\n", s[statDropped])

		b.WriteString("# HELP ebpf_audit_filtered_total 커널 단계에서 걸러낸 이벤트 수\n")
		b.WriteString("# TYPE ebpf_audit_filtered_total counter\n")
		fmt.Fprintf(&b, "ebpf_audit_filtered_total %d\n", s[statFiltered])

		b.WriteString("# HELP ebpf_audit_containers 추적 중인 컨테이너 cgroup 수\n")
		b.WriteString("# TYPE ebpf_audit_containers gauge\n")
		fmt.Fprintf(&b, "ebpf_audit_containers %d\n", res.count())

		_, _ = w.Write([]byte(b.String()))
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("메트릭 서버 종료: %v\n", err)
	}
}
