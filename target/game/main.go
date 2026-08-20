// 안티치트 실습용 미니 게임 타깃.
//
// 이 "게임"은 500ms 마다 플레이어 체력을 갱신한다. 정상 로직은 체력을
// 0~100 범위로 유지한다. 하지만 -cheat 플래그를 주면 메모리 조작 치트를
// 흉내내어 체력을 9999(비정상)로 세팅한다.
//
// 12번 안티치트는 이 setHealth 함수에 uprobe 를 붙여, 넘어오는 인자가
// 게임 규칙(<=100)을 위반하는 순간을 잡아낸다. = 서버측 유효성 검사를
// 커널 레벨에서 하는 셈. 치트 프로그램을 수정하지 않고도 탐지한다.
//
//	go build -o /opt/lab/bin/game ./target/game
//	/opt/lab/bin/game            # 정상 플레이
//	/opt/lab/bin/game -cheat     # 치트 (체력 9999)
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

//go:noinline
func setHealth(hp int) int {
	// 실제 게임이라면 여기서 렌더링/상태 반영. 지금은 그냥 반환.
	return hp
}

func main() {
	cheat := flag.Bool("cheat", false, "메모리 조작 치트 흉내 (체력 9999)")
	flag.Parse()

	fmt.Printf("game 시작 pid=%d cheat=%v\n", os.Getpid(), *cheat)
	hp := 100
	for tick := 0; ; tick++ {
		if *cheat {
			hp = 9999 // 🔴 치트: 규칙(<=100) 위반
		} else {
			hp = 90 + (tick % 11) // 정상: 90~100
		}
		got := setHealth(hp)
		fmt.Printf("tick %d: HP=%d\n", tick, got)
		time.Sleep(500 * time.Millisecond)
	}
}
