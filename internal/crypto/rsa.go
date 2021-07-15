package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

const (
	RsaKeyByFile = iota + 1
	RsaKeyByData
	PrivateKey
	PublicKey
)

type RsaKey struct {
	PrivateKey string
	PublicKey  string
}

type rsaClient struct {
}

type RsaClient interface {
	GenRsaPriBlock(bits int) (*rsa.PrivateKey, *pem.Block, error)
	GenRsaPubBlock(privateKey *rsa.PrivateKey) (*pem.Block, error)
	EncodeBlockByFile(block *pem.Block, fileName string) error
	EncodeBlockByData(block *pem.Block) string
	GenRsaKey(bits, method int) (*RsaKey, error)
}

func NewRsaClient() RsaClient {
	return &rsaClient{}
}

//私钥
func (r *rsaClient) GenRsaPriBlock(bits int) (*rsa.PrivateKey, *pem.Block, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	return privateKey, block, nil
}

//公钥
func (r *rsaClient) GenRsaPubBlock(privateKey *rsa.PrivateKey) (*pem.Block, error) {
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPkix,
	}
	return block, err
}

func (r *rsaClient) EncodeBlockByFile(block *pem.Block, fileName string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	if err = pem.Encode(file, block); err != nil {
		return err
	}
	return nil
}

func (r *rsaClient) EncodeBlockByData(block *pem.Block) string {
	bytes := pem.EncodeToMemory(block)
	return string(bytes)
}

func (r *rsaClient) GenRsaKey(bits, method int) (*RsaKey, error) {
	rsaKey := &RsaKey{}
	switch method {
	case RsaKeyByFile:
		p, priBlock, err := r.GenRsaPriBlock(bits)
		err = r.EncodeBlockByFile(priBlock, "private.pem")
		if err != nil {
			return nil, err
		}
		pubBlock, err := r.GenRsaPubBlock(p)
		err = r.EncodeBlockByFile(pubBlock, "public.pem")
		if err != nil {
			return nil, err
		}
		break
	case RsaKeyByData:
		p, priBlock, err := r.GenRsaPriBlock(bits)
		if err != nil {
			return nil, err
		}
		privateKey := r.EncodeBlockByData(priBlock)
		pubBlock, err := r.GenRsaPubBlock(p)
		if err != nil {
			return nil, err
		}
		publicKey := r.EncodeBlockByData(pubBlock)
		rsaKey = &RsaKey{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}
	}
	return rsaKey, nil
}

/*
//生成公钥私钥文件
func GenRsaKeyFile(bits int) error {
	//私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	if err = pem.Encode(file, block); err != nil {
		return err
	}

	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPkix,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

//生成公钥私钥文件
func GenRsaKeyData(bits int) (*RsaKey, error) {
	rsaKey := &RsaKey{}
	//私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}

	bPrivateKey := pem.EncodeToMemory(block)
	rsaKey.PrivateKey = string(bPrivateKey)

	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derPkix,
	}
	bPublicKey := pem.EncodeToMemory(block)
	rsaKey.PublicKey = string(bPublicKey)
	return rsaKey, nil
}

//加密
func RsaEncryptByFile(origData []byte) ([]byte, error) {
	publicKey, err := ioutil.ReadFile("public.pem")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

func RsaDecrypt() {

}
*/
