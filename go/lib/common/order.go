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

package common

import (
	"encoding/binary"
	"unsafe"
)

var Order = binary.BigEndian
var Htons = byteSwap16Noop
var Ntohs = byteSwap16Noop

func init() {
	if isLittleEndian() {
		Htons = byteSwap16
		Ntohs = byteSwap16
	}
}

func isLittleEndian() bool {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	return (b == 0x04)
}

func byteSwap16(v uint16) uint16 {
	return ((v >> 8) & 0xFF) | ((v & 0xFF) << 8)
}

func byteSwap16Noop(v uint16) uint16 {
	return v
}
