//go:build !team

package main

import (
	"fmt"

	"fenzi/cli/internal/tui"
)

// includedTeam is true in a build that carries the local team server. This
// build does not: the team control plane is the hosted service.
const includedTeam = false

func cmdServer(e env, args []string) (int, error) {
	u := tui.ForOutput(e.stderr)
	u.Blank()
	u.Println(fmt.Sprintf("  %s %s", u.Bold("!"), u.Bold("fenzi server is not part of this build.")))
	u.Note("The team control plane is hosted. Sign this machine in with fenzi login.")
	u.Blank()
	return 0, quietExit(1)
}
