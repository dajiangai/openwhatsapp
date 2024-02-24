package utils

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

// RandBytes .
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// IntToBigEndianBytes .
func IntToBigEndianBytes(n uint32) []byte {
	//buff := make([]byte, 4)
	//binary.BigEndian.PutUint32(buff, n)
	//return buff
	return big.NewInt(int64(n)).Bytes()
}

func UInt32ToBigEndianBytes(n uint32, l int) []byte {
	buff := make([]byte, 4)
	binary.BigEndian.PutUint32(buff, n)
	return buff[4-l:]
}

// IntToLittleEndianBytes .
func IntToLittleEndianBytes(n uint32) []byte {
	//buff := make([]byte, 4)
	//binary.LittleEndian.PutUint32(buff, n)
	//return buff
	b := big.NewInt(int64(n)).Bytes()

	size := len(b)
	maxIdx := size - 1

	for i := 0; i < size/2; i++ {
		b[i], b[maxIdx-i] = b[maxIdx-i], b[i]
	}

	return b
}

// BigEndianBytesToInt 大端排列的Byte转换成int
func BigEndianBytesToInt(buf []byte) int {
	b := big.NewInt(0).SetBytes(buf)

	return int(b.Int64())
}
