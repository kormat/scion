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

// This file handles IO using the POSIX(/BSD) socket API.

package main

import (
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

// readPosixInput reads packets from a single POSIX(/BSD) socket. It retrieves
// buffers via getPktBuf, and fills in some important packet metadata such as
// the overlay source/destination addresses, the direction the packet came
// from, and the list of interfaces that it could belong to (as some sockets
// may be associated with more than one interface).
func (r *Router) readPosixInput(in *net.UDPConn, dirFrom rpkt.Dir, ifids []spath.IntfID,
	labels prometheus.Labels, q chan *rpkt.RtrPkt) {
	defer liblog.PanicLog()
	log.Info("Listening", "addr", in.LocalAddr())
	dst := in.LocalAddr().(*net.UDPAddr)
	inputLoops := metrics.InputLoops.With(labels)
	inputProcessTime := metrics.InputProcessTime.With(labels)
	pktsRecv := metrics.PktsRecv.With(labels)
	bytesRecv := metrics.BytesRecv.With(labels)
	for { // Run forever.
		inputLoops.Inc()
		rp := r.getPktBuf()
		rp.DirFrom = dirFrom
		start := time.Now()
		length, src, err := in.ReadFromUDP(rp.Raw)
		if err != nil {
			log.Error("Error reading from socket", "socket", dst, "err", err)
			continue
		}
		t := time.Now().Sub(start).Seconds()
		inputProcessTime.Add(t)
		rp.TimeIn = time.Now()
		rp.Raw = rp.Raw[:length] // Set the length of the slice
		rp.Ingress.Src = src
		rp.Ingress.Dst = dst
		rp.Ingress.IfIDs = ifids
		pktsRecv.Inc()
		bytesRecv.Add(float64(length))
		// TODO(kormat): experiment with performance by calling processPacket directly instead.
		q <- rp
	}
}

type posixOutputFunc func(common.RawBytes, *net.UDPAddr) (int, error)

// XXXXXXX writePosixOutput writes packets to a POSIX(/BSD) socket using the provided
// function (a wrapper around net.UDPConn.WriteToUDP or net.UDPConn.Write).
func (r *Router) mkPosixOutput(labels prometheus.Labels, f posixOutputFunc) rpkt.OutputFunc {
	outProcTime := metrics.OutputProcessTime.With(labels)
	bytesSent := metrics.BytesSent.With(labels)
	pktsSent := metrics.PktsSent.With(labels)
	return func(rp *rpkt.RtrPkt, dst *net.UDPAddr) {
		defer r.recyclePkt(rp)
		start := time.Now()
		if count, err := f(rp.Raw, dst); err != nil {
			rp.Error("Error sending packet", "err", err, "dst", dst)
			return
		} else if count != len(rp.Raw) {
			rp.Error("Unable to write full packet", "len", len(rp.Raw), "written", count)
			return
		}
		t := time.Now().Sub(start).Seconds()
		outProcTime.Add(t)
		bytesSent.Add(float64(len(rp.Raw)))
		pktsSent.Inc()
	}
}
