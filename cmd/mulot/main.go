package main

import (
	"log"
	"os"

	"github.com/io-tl/mulot/internal/mcp"
)

func main() {
	log.SetFlags(0)
	if err := mcp.Run(); err != nil {
		log.Fatalf("mulot: %v", err)
		os.Exit(1)
	}
}
