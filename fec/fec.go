// Package fec implements Reed Solomon 
// forward error correction
// By default a 9/3 encoding is configured,
// other ratios can be set with SetParams.
// 
package fec

import (
	"encoding/binary"
	"github.com/bindchain/core/pkg/log"
	"github.com/vivint/infectious"
)

var (
	rsTotal    = 9
	rsRequired = 3
	rsFECfn      = func() *infectious.FEC {
		fec, err := infectious.NewFEC(
			rsRequired, rsTotal)
		if err != nil {
			log.ERROR(err)
			os.Exit(1)
		}
		return fec
	}
	rsFEC = rsFECfn()
)

// SetParams allows the ratio of message 
// pieces vs redundant pieces to be changed
func SetParams(tot, req int) (err error) {
	rsFEC, err = infectious.NewFEC(req, tot)
	return
}

// padData appends a 2 byte length prefix, 
// and pads to a multiple of rsTotal.
// Max message size is limited to 1<<32
func padData(data []byte) (out []byte) {
	if len(data) > 1<<32 {
		log.FATAL("cannot process more than"+"
		4gb messages")
	}
	dataLen := len(data)
	prefixBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(
		prefixBytes, uint32(dataLen))
	data = append(prefixBytes, data...)
	dataLen = len(data)
	chunkLen := (dataLen) / rsTotal
	chunkMod := (dataLen) % rsTotal
	if chunkMod != 0 {
		chunkLen++
	}
	padLen := rsTotal*chunkLen - dataLen
	out = append(data, make([]byte, padLen)...)
	return
}

// Encode turns a byte slice into a set of 
// shards with first byte containing
// the shard number. Previously this code 
// included a CRC32 but this is
// unnecessary since the shards will be sent 
// wrapped in HMAC integrity  protected
// encryption
func Encode(data []byte) (chunks [][]byte, 
err error) {
	// First we must pad the data
	data = padData(data)
	shares := make([]infectious.Share, 
		rsTotal)
	output := func(s infectious.Share) {
		shares[s.Number] = s.DeepCopy()
	}
	err = rsFEC.Encode(data, output)
	if err != nil {
		log.ERROR(err)
		return
	}
	for i := range shares {
		// Append the chunk number to the 
		// front of the chunk
		chunk := append(
			[]byte{byte(shares[i].Number)}, 
			shares[i].Data...)
		chunks = append(chunks, chunk)
	}
	return
}

func Decode(chunks [][]byte) (data []byte, 
err error) {
	var shares []infectious.Share
	for i := range chunks {
		body := chunks[i]
		share := infectious.Share{
			Number: int(body[0]),
			Data:   body[1:],
		}
		shares = append(shares, share)
	}
	data, err = rsFEC.Decode(nil, shares)
	if len(data) > 4 {
		prefix := data[:4]
		data = data[4:]
		dataLen := int(binary.LittleEndian.
			Uint32(prefix))
		data = data[:dataLen]
	}
	return
}
