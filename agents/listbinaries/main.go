// Command listbinaries prints the binary paths an agent's image must
// contain for one processor, one per line. check-images.sh uses it so the
// image check reads agent.yaml through the same loader as the CLI.
//
//	go run ./agents/listbinaries <agent> <amd64|arm64>
package main

import (
	"fmt"
	"os"

	"boundlane/agents"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: listbinaries <agent> <amd64|arm64>")
		os.Exit(2)
	}
	e, err := agents.Get(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bins, err := e.BinariesFor(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(bins) == 0 {
		fmt.Fprintf(os.Stderr, "%s: agent.yaml lists no binary for %s\n", e.Name, os.Args[2])
		os.Exit(1)
	}
	for _, b := range bins {
		fmt.Println(b)
	}
}
