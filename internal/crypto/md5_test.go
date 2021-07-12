package crypto

import (
	"fmt"
	"testing"
)

func TestGetMd5(t *testing.T) {
	md5 := GetMd5("hello")
	fmt.Println(md5)
}
