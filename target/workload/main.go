// uprobe 실습용 타깃 프로그램.
//
// 500ms 마다 compute(n) 를 호출한다. 04번 예제가 이 바이너리의 main.compute
// 심볼에 uprobe 를 붙여서 인자 n 을 훔쳐본다.
//
//	make workload      # /lab/bin/workload 로 빌드
//	./bin/workload &   # 컨테이너 안에서 실행
package main

import (
	"fmt"
	"os"
	"time"
)

// go:noinline 이 없으면 인라인되어 심볼이 사라지거나 진입점이 달라질 수 있다.
// 또 빌드할 때 -ldflags "-s -w" 를 주면 심볼 테이블이 날아가 uprobe 를 못 붙인다.
//
//go:noinline
func compute(n int) int {
	sum := 0
	for i := 0; i <= n; i++ {
		sum += i * i
	}
	return sum
}

func main() {
	fmt.Printf("workload 시작 pid=%d — 500ms 마다 compute() 호출\n", os.Getpid())
	for n := 1; ; n++ {
		out := compute(n)
		fmt.Printf("compute(%d) = %d\n", n, out)
		time.Sleep(500 * time.Millisecond)
	}
}
