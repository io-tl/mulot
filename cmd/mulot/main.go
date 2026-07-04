package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/io-tl/mulot/internal/envcfg"
	"github.com/io-tl/mulot/internal/mcp"
)

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `mulot - MCP server for browser-driven security testing

mulot speaks MCP over stdio; it is meant to be launched by an MCP client
(Claude Code, Claude Desktop, etc.), not run interactively.

Usage:
  mulot [flags]

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment variables:\n")
		for _, v := range envcfg.Vars {
			fmt.Fprintf(os.Stderr, "  %-18s %s\n", v.Name, v.Desc)
		}
	}
	flag.Parse()

	if err := mcp.Run(); err != nil {
		log.Fatalf("mulot: %v", err)
		os.Exit(1)
	}
}
