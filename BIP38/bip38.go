package main

import (
	"reflect"

	"crypto/aes"
	"crypto/sha256"

	"cosmossdk.io/errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/decred/base58"
	"golang.org/x/crypto/scrypt"
)

func createHash(passphrase string) []byte {
	hash := sha256.New()
	hash.Write([]byte(passphrase))
	return hash.Sum(nil)
}

// double sha256 hash
func doublesha256(b []byte) []byte {
	hash := sha256.Sum256(b)
	hash = sha256.Sum256(hash[:])
	return hash[:]
}

// RIPEMD-160哈希
// 已弃用：RIPEMD-160 是旧版哈希，不应用于新应用程序。此外，这个包现在和将来都不会提供优化的实现。
// 所以 使用SHA-256（crypto/sha256）替代
func ripemd160Hash(b []byte) []byte {
	// hasher := ripemd160.New()
	// hasher.Write(b)
	// return hasher.Sum(nil)
	hash := sha256.Sum256(b)
	return hash[:]
}

// Bip38 encrypt
func Bip38Encrypt(wifStr, passphrase string) (string, error) {
	// try decrypt wif type key
	wif, err := btcutil.DecodeWIF(wifStr)
	if err != nil {
		return "", err
	}
	// generate salt
	salt := ripemd160Hash(wif.PrivKey.PubKey().SerializeCompressed())[:4]
	// use scrypt generate key
	scryptKey, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 8, 64)
	if err != nil {
		return "", err
	}
	derivedHalf1 := scryptKey[:32]
	derivedHalf2 := scryptKey[32:]
	block, err := aes.NewCipher(derivedHalf2)
	if err != nil {
		return "", err
	}
	// privateKey 16 byte encryte
	xorbytes := func(a, b []byte) []byte {
		n := len(a)
		xored := make([]byte, n)
		for i := 0; i < n; i++ {
			xored[i] = a[i] ^ b[i]
		}
		return xored
	}
	privKeyBytes := wif.PrivKey.Serialize()
	encryptedHalf1 := xorbytes(privKeyBytes[:16], derivedHalf1[:16])
	encryptedHalf2 := xorbytes(privKeyBytes[16:], derivedHalf1[16:])

	encryptedBytes := make([]byte, 32)
	block.Encrypt(encryptedBytes[:16], encryptedHalf1)
	block.Encrypt(encryptedBytes[16:], encryptedHalf2)

	// generate bip38 type
	bip38Key := append([]byte{0x01, 0x42, 0xC0}, salt...)
	bip38Key = append(bip38Key, encryptedBytes...)

	// add checkSum
	checksum := doublesha256(bip38Key)[:4]
	bip38Key = append(bip38Key, checksum...)

	// base58 encode
	return base58.Encode(bip38Key), nil
}

func BIP38Decrypt(encryptedKey, passphrase, network string) (string, error) {
	decoded := base58.Decode(encryptedKey)

	// check checkSum
	checksum := decoded[len(decoded)-4:]
	hash := doublesha256(decoded[:len(decoded)-4])
	if !reflect.DeepEqual(hash[:4], checksum) {
		return "", errors.New("checksum vaild failed")
	}

	// get salt
	salt := decoded[3:7]
	encryptedHalf1 := decoded[7:23]
	encryptedHalf2 := decoded[23:39]

	// use scrypt generate key
	scryptKey, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 8, 64)
	if err != nil {
		return "", errors.Wrap(err, "scrypt key generate failed")
	}

	derivedHalf1 := scryptKey[:32]
	derivedHalf2 := scryptKey[32:]

	block, err := aes.NewCipher(derivedHalf2)
	if err != nil {
		return "", errors.Wrap(err, "AES password generate failed")
	}

	decryptedHalf1 := make([]byte, 16)
	block.Decrypt(decryptedHalf1, encryptedHalf1)
	decryptedHalf2 := make([]byte, 16)
	block.Decrypt(decryptedHalf2, encryptedHalf2)

	privKeyBytes := append(decryptedHalf1, decryptedHalf2...)
	for i := 0; i < 32; i++ {
		privKeyBytes[i] ^= derivedHalf1[i]
	}

	// 将解密后的私钥字节切片转换为 *btcec.PrivateKey 类型
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// 使用解密的私钥生成WIF格式
	wif, err := btcutil.NewWIF(privKey, GetNetwork(network), true)
	if err != nil {
		return "", errors.Wrap(err, "generate wirf failed")
	}

	return wif.String(), nil
}
