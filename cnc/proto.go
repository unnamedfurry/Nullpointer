package main

import (
	"encoding/hex"
	"sync"
)

const ProtoKeyLen = 32
const ProtoMagicBot = 0x4E50

var protoKey []byte
var protoOnce sync.Once

func protoInit(keyHex string) {
	protoOnce.Do(func() {
		if keyHex == "" {
			return
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil || len(key) < ProtoKeyLen {
			return
		}
		protoKey = make([]byte, ProtoKeyLen)
		copy(protoKey, key)
	})
}

func protoEncrypt(buf []byte) {
	if len(protoKey) == 0 {
		return
	}
	for i := range buf {
		buf[i] ^= protoKey[i%ProtoKeyLen]
	}
}

func protoDecrypt(buf []byte) {
	protoEncrypt(buf)
}

func protoReady() bool {
	return len(protoKey) > 0
}
