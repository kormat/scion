// Copyright 2016 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"crypto/aes"
	"crypto/cipher"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
)

const (
	ErrorCipherFailure = "Unable to initalize AES cipher"
	ErrorCiphertextLen = "Ciphertext isn't a multiple of the block size"
)

var iv []byte
var bmCleanQ chan cipher.BlockMode
var bmDirtyQ chan cipher.BlockMode

func InitAES(key common.RawBytes) (cipher.Block, *common.Error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, common.NewError(ErrorCipherFailure, log.Ctx{"err": err})
	}
	iv = make([]byte, block.BlockSize())
	go bmClean(block)
	return block, nil
}

type bmCleanInt interface {
	cipher.BlockMode
	SetIV([]byte)
}

func bmClean(block cipher.Block) {
	bmCleanQ = make(chan cipher.BlockMode, 1024)
	bmDirtyQ = make(chan cipher.BlockMode, 1024)
	for bm := range bmDirtyQ {
		bm := bm.(bmCleanInt)
		bm.SetIV(iv)
		bmCleanQ <- bm
	}
}

func CBCMac(block cipher.Block, msg common.RawBytes) (common.RawBytes, *common.Error) {
	blkSize := block.BlockSize()
	if len(msg)%blkSize != 0 {
		return nil, common.NewError(ErrorCiphertextLen, "textLen", len(msg), "blkSize", blkSize)
	}
	var mode cipher.BlockMode
	select {
	case mode = <-bmCleanQ:
	default:
		mode = cipher.NewCBCEncrypter(block, iv)
	}
	// Work in-place
	mode.CryptBlocks(msg, msg)
	bmDirtyQ <- mode
	// Return last block
	return msg[len(msg)-blkSize:], nil
}
