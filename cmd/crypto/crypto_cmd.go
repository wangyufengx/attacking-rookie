package crypto

import (
	"flag"
	"github.com/attacking-rookie/internal/crypto"
	"log"
)

var (
	Cmd = flag.NewFlagSet("crypto", flag.ExitOnError)

	Md5       string
	GenRsaKey int
)

func InitCrypto() {
	Cmd.StringVar(&Md5, "md5", "hello md5", "MD5加密")
	Cmd.IntVar(&GenRsaKey, "rsa-key", 32, "生产私钥公钥")
}

func RunCmd() {
	switch {
	case Md5 != "":
		md5 := crypto.GetMd5(Md5)
		log.Printf("md5:%s", md5)
	case GenRsaKey != 32:
		crypto.GetMd5(Md5)
	}
}
