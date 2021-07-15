package crypto

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

/**
 * @Author wyf
 * @Date 2021/7/15 9:20
 **/

func TestGenRsaKeyData(t *testing.T) {
	client := NewRsaClient()
	rsaKeyData, err := client.GenRsaKey(1024, RsaKeyByData)
	assert.Nil(t, err)
	fmt.Println(rsaKeyData.PrivateKey)
	fmt.Println(rsaKeyData.PublicKey)
}
