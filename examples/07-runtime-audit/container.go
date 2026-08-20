package main

// 컨테이너 귀속(attribution).
//
// eBPF 는 컨테이너라는 개념을 모른다. 커널이 아는 것은 cgroup 뿐이고,
// 컨테이너 런타임이 컨테이너마다 cgroup 을 하나씩 만들기 때문에
// "cgroup id -> 컨테이너" 매핑이 곧 귀속 로직이 된다.
//
//	cgroup v2 에서 cgroup id == cgroup 디렉터리의 inode 번호
//	-> bpf_get_current_cgroup_id() 가 준 값을 stat(2) 결과와 맞추면 된다.
//
// Kubernetes 환경도 원리가 같다. 경로만 다르다:
//
//	docker:      /sys/fs/cgroup/docker/<64-hex>
//	systemd:     /sys/fs/cgroup/system.slice/docker-<64-hex>.scope
//	kubelet:     /sys/fs/cgroup/kubepods/besteffort/pod<uid>/<64-hex>
//	containerd:  .../cri-containerd-<64-hex>.scope
//
// 이름(ebpf-victim 같은)은 커널에 없다. 런타임 API 에 물어봐야 한다.
// 여기서는 도커 소켓에 HTTP 로 물어본다 (Kubernetes 라면 CRI 또는 API 서버).

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var hex64 = regexp.MustCompile(`[0-9a-f]{64}`)

type containerInfo struct {
	CgroupID   uint64
	CgroupPath string
	ID         string // 64자 전체 ID (알아낸 경우)
	Name       string // 런타임에서 조회한 이름
}

func (c containerInfo) Display() string {
	switch {
	case c.Name != "":
		return c.Name
	case c.ID != "":
		return c.ID[:12]
	default:
		return filepath.Base(c.CgroupPath)
	}
}

type resolver struct {
	cgroupRoot string
	dockerSock string

	mu      sync.RWMutex
	byID    map[uint64]containerInfo
	scanned int
}

func newResolver(cgroupRoot, dockerSock string) *resolver {
	return &resolver{
		cgroupRoot: cgroupRoot,
		dockerSock: dockerSock,
		byID:       map[uint64]containerInfo{},
	}
}

// refresh 는 cgroup 트리를 걸어 컨테이너 cgroup 을 찾고, 가능하면 이름까지 붙인다.
func (r *resolver) refresh() error {
	names := dockerNames(r.dockerSock) // 실패하면 빈 맵. 이름 없이도 동작해야 한다.

	found := map[uint64]containerInfo{}
	err := filepath.WalkDir(r.cgroupRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 권한 없는 하위 트리는 조용히 건너뛴다
		}
		if !d.IsDir() {
			return nil
		}
		// 너무 깊이 들어가지 않는다 (cgroup 트리는 컨테이너별로 더 하위가 있다)
		if strings.Count(strings.TrimPrefix(path, r.cgroupRoot), "/") > 6 {
			return fs.SkipDir
		}
		m := hex64.FindString(path)
		if m == "" {
			return nil
		}
		id, err := cgroupIDOf(path)
		if err != nil {
			return nil
		}
		found[id] = containerInfo{
			CgroupID:   id,
			CgroupPath: path,
			ID:         m,
			Name:       names[m],
		}
		return nil
	})

	r.mu.Lock()
	r.byID = found
	r.scanned++
	r.mu.Unlock()
	return err
}

func (r *resolver) lookup(cgroupID uint64) (containerInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[cgroupID]
	return c, ok
}

// findByName 은 컨테이너 이름 또는 ID prefix 로 찾는다.
func (r *resolver) findByName(q string) (containerInfo, bool) {
	q = strings.TrimPrefix(q, "/")
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.byID {
		if c.Name == q || strings.HasPrefix(c.ID, q) {
			return c, true
		}
	}
	return containerInfo{}, false
}

func (r *resolver) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// cgroupIDOf 는 cgroup v2 디렉터리의 inode 번호(= cgroup id)를 읽는다.
func cgroupIDOf(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat 결과를 해석할 수 없다: %s", path)
	}
	return uint64(st.Ino), nil
}

// dockerNames 는 도커 소켓에 물어서 "전체 컨테이너 ID -> 이름" 맵을 만든다.
// 소켓이 없거나 실패하면 빈 맵을 돌려주고, 호출자는 ID 만으로 계속 동작한다.
func dockerNames(sock string) map[string]string {
	out := map[string]string{}
	if sock == "" {
		return out
	}
	if _, err := os.Stat(sock); err != nil {
		return out
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}
	// 호스트 이름은 아무 값이나 넣어도 된다. 실제 연결은 위 DialContext 가 결정한다.
	resp, err := client.Get("http://docker/containers/json?all=1")
	if err != nil {
		return out
	}
	defer resp.Body.Close()

	var list []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return out
	}
	for _, c := range list {
		if len(c.Names) > 0 {
			out[c.ID] = strings.TrimPrefix(c.Names[0], "/")
		}
	}
	return out
}
