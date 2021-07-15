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

const RsaKeyBits = 1024

func InitCrypto() {
	Cmd.StringVar(&Md5, "md5", "hello md5", "MD5加密")
	Cmd.IntVar(&GenRsaKey, "rsa-key", 0, "产生私钥公钥, 0:文件形式,1:标准输出形式")
}

func RunCmd() {
	switch {
	case Md5 != "hello md5":
		md5 := crypto.GetMd5(Md5)
		log.Printf("md5:%s", md5)
	case GenRsaKey != 0:
		client := crypto.NewRsaClient()
		key, _ := client.GenRsaKey(RsaKeyBits, GenRsaKey)
		log.Printf("privateKey:%v", key.PrivateKey)
		log.Printf("publicKey:%v", key.PublicKey)
	}
}
