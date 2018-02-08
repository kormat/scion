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

package rcmn

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra/rudp"
)

var _ common.Payload = (*RUdpPld)(nil)

type RUdpPld struct {
	hdr *rudp.Hdr
	pld common.RawBytes
}

func NewRUdpPld(pld *ctrl.SignedPld, flags rudp.Flags, id common.RawBytes) (*RUdpPld, error) {
	rawPld, err := pld.PackPld()
	if err != nil {
		return nil, err
	}
	return &RUdpPld{hdr: rudp.NewHdr(flags, id), pld: rawPld}, nil
}

func NewRUdpPldFromRaw(b common.RawBytes) *RUdpPld {
	return &RUdpPld{hdr: rudp.NewHdrFromRaw(b[:rudp.HdrLen]), pld: b[rudp.HdrLen:]}
}

func (r *RUdpPld) Pld() (*ctrl.SignedPld, error) {
	return ctrl.NewSignedPldFromRaw(r.pld)
}

func (r *RUdpPld) Copy() (common.Payload, error) {
	return &RUdpPld{hdr: r.hdr.Copy(), pld: append(common.RawBytes{}, r.pld...)}, nil
}

func (r *RUdpPld) Len() int {
	return rudp.HdrLen + len(r.pld)
}

func (r *RUdpPld) WritePld(b common.RawBytes) (int, error) {
	if len(b) < r.Len() {
		return 0, common.NewBasicError("Unable to write RUdpPld - buffer is too small", nil,
			"min", r.Len(), "actual", len(b))
	}
	r.hdr.Write(b)
	return rudp.HdrLen + copy(b[rudp.HdrLen:], r.pld), nil
}

func (r *RUdpPld) String() string {
	return fmt.Sprintf("Hdr: %s Pld: %dB", r.hdr, len(r.pld))
}
