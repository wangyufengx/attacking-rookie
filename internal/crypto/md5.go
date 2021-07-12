package crypto

import (
	"crypto/md5"
	"fmt"
)

func GetMd5(data string) string {
	hash := md5.New()
	hash.Write([]byte(data))
	return fmt.Sprintf("%x", hash.Sum(nil))
}
