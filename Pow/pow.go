package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"crypto/sha256"
)

type Block struct {
	Data      string
	PrevHash  string
	Nonce     int
	Hash      string
	Difficult int
}

func (b *Block) calculateHash() string {
	record := b.Data + b.PrevHash + fmt.Sprintf("%d", b.Nonce)
	h := sha256.New()
	h.Write([]byte(record))
	hahsed := h.Sum(nil)
	return hex.EncodeToString(hahsed)
}

func NewBlock(data, preHash string, difficulty int) *Block {
	block := &Block{Data: data, PrevHash: preHash, Difficult: difficulty}
	block.mine()
	return block
}

func (b *Block) mine() {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-b.Difficult))
	for {
		hash := b.calculateHash()
		var hashInt big.Int
		hashInt.SetString(hash, 16)
		if hashInt.Cmp(target) == 1 {
			b.Hash = hash
			break
		} else {
			b.Nonce++
		}
	}
}

func main() {
	// 创建区块链
	genesisBlock := NewBlock("Genesis Block", "", 20)
	fmt.Printf("Genesis Block Hash: %s\n", genesisBlock.Hash)

	secondBlock := NewBlock("Second Block", genesisBlock.Hash, 20)
	fmt.Printf("Second Block Hash: %s\n", secondBlock.Hash)

	thirdBlock := NewBlock("Third Block", secondBlock.Hash, 20)
	fmt.Printf("Third Block Hash: %s\n", thirdBlock.Hash)
}
