// Copyright 2018 ETH Zurich
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

// RUDP (Reliable UDP) is a simple UDP protocol with ACKs.
//
// Header format:
//   0B       1        2        3        4        5        6        7
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   | Flags  |                           PacketID                           |
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//
// The flags field bits are allocated as follows:
// - 0x01 NEED_ACK. This indicates a packet that requires an ACK.
// - 0x02 ACK. This is used to acknowledge a NEED_ACK packet, re-using the PacketID.
// For packets which don't need any acknowledgment, the flags field is 0.
package rudp

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
)

type Flags uint8

const (
	FlagNeedAck Flags = 0x01
	FlagAck     Flags = 0x02
	HdrLen            = 8
)

type Hdr struct {
	flags Flags
	Id    common.RawBytes
}

func NewHdr(flags Flags, id common.RawBytes) *Hdr {
	return &Hdr{flags: flags, Id: id}
}

func NewHdrFromRaw(b common.RawBytes) *Hdr {
	return NewHdr(Flags(b[0]), b[1:HdrLen])
}

func (h *Hdr) IsNeedAck() bool {
	return (h.flags & FlagNeedAck) > 0
}

func (h *Hdr) IsAck() bool {
	return (h.flags & FlagAck) > 0
}

func (h *Hdr) Write(b common.RawBytes) {
	_ = b[HdrLen]
	b[0] = uint8(h.flags)
	copy(b[1:], h.Id)
}

func (h *Hdr) Pack() common.RawBytes {
	b := make(common.RawBytes, HdrLen)
	h.Write(b)
	return b
}

func (h *Hdr) String() string {
	return fmt.Sprintf("Id: %014x Flags: %s", h.Id, h.FlagsStr())
}

func (h *Hdr) FlagsStr() string {
	switch h.flags {
	case 0x00:
		return "None (0x00)"
	case 0x01:
		return "NEED_ACK (0x01)"
	case 0x02:
		return "ACK (0x02)"
	default:
		return fmt.Sprintf("UNKNOWN (%02x)", h.flags)
	}
}
