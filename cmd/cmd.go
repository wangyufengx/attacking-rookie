package cmd

import (
	"flag"
	"github.com/attacking-rookie/cmd/crypto"
)

func InitCmd() {
	flag.Parse()

	args := flag.Args()
	if len(args) <= 0 {
		return
	}

	switch args[0] {
	case "crypto":
		crypto.InitCrypto()
		_ = crypto.Cmd.Parse(args[1:])
		crypto.RunCmd()
	}

}
