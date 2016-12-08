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

// This file handles the router setup, from getting the config loaded, to
// configuring the network interfaces, and starting the input goroutines.
// Support for POSIX(/BSD) sockets is included here, with hooks to allow other
// network stacks to be loaded instead/additionally.

package main

import (
	"fmt"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/gocapability/capability"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

const chanBufSize = 32

type setupNetHook func(r *Router) (rpkt.HookResult, *common.Error)
type setupAddLocalHook func(r *Router, idx int, over *overlay.UDP, labels prometheus.Labels) (
	rpkt.HookResult, *common.Error)
type setupAddExtHook func(r *Router, intf *netconf.Interface, labels prometheus.Labels) (
	rpkt.HookResult, *common.Error)

// Setup hooks enables the network stack to be modular. Any network stack that
// wants to be included defines its own init function which adds hooks to these
// hook slices. See setup-hsr.go for an example.
var setupNetStartHooks []setupNetHook
var setupAddLocalHooks []setupAddLocalHook
var setupAddExtHooks []setupAddExtHook
var setupNetFinishHooks []setupNetHook

// setup creates the router's channels and map, loads the configuration, and
// sets up the rpkt package.
func (r *Router) setup(confDir string) *common.Error {
	r.locOutQs = make(map[int]rpkt.OutputQueue)
	r.intfOutQs = make(map[spath.IntfID]rpkt.OutputQueue)
	r.freePkts = make(chan *rpkt.RtrPkt, 1024)
	r.revInfoQ = make(chan common.RawBytes)

	if err := conf.Load(r.Id, confDir); err != nil {
		return err
	}
	log.Debug("Topology loaded", "topo", conf.C.BR)
	log.Debug("AS Conf loaded", "conf", conf.C.ASConf)

	// Configure the rpkt package with the callbacks it needs.
	rpkt.Init(r.locOutQs, r.intfOutQs, r.ProcessIFStates, r.RevTokenCallback)
	return nil
}

// setupNet configures networking for the router, using any setup hooks that
// have been registered, and immediately drops any capabilities that might have
// been needed.
func (r *Router) setupNet() *common.Error {
	// If there are other hooks, they should install themselves via init(), so
	// they appear before the posix ones.
	setupAddLocalHooks = append(setupAddLocalHooks, setupPosixAddLocal)
	setupAddExtHooks = append(setupAddExtHooks, setupPosixAddExt)
	// Run startup hooks, if any.
Lstart:
	for _, f := range setupNetStartHooks {
		ret, err := f(r)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break Lstart
		}
	}
	// Iterate over local addresses, configuring them via provided hooks.
	for i, a := range conf.C.Net.LocAddr {
		labels := prometheus.Labels{"id": fmt.Sprintf("loc:%d", i)}
	Llocal:
		for _, f := range setupAddLocalHooks {
			ret, err := f(r, i, a, labels)
			switch {
			case err != nil:
				return err
			case ret == rpkt.HookContinue:
				continue
			case ret == rpkt.HookFinish:
				break Llocal
			}
		}
	}
	// Export prometheus metrics over http interface, if specified.
	if len(*httpAddr) != 0 {
		metrics.Export([]string{*httpAddr})
	}
	// Iterate over interfaces, configuring them via provided hooks.
	for _, intf := range conf.C.Net.IFs {
		labels := prometheus.Labels{"id": fmt.Sprintf("intf:%d", intf.Id)}
	Lintf:
		for _, f := range setupAddExtHooks {
			ret, err := f(r, intf, labels)
			switch {
			case err != nil:
				return err
			case ret == rpkt.HookContinue:
				continue
			case ret == rpkt.HookFinish:
				// Break out of switch statement and inner loop.
				break Lintf
			}
		}
	}
	// Run finish hooks, if any.
Lfinish:
	for _, f := range setupNetFinishHooks {
		ret, err := f(r)
		switch {
		case err != nil:
			return err
		case ret == rpkt.HookContinue:
			continue
		case ret == rpkt.HookFinish:
			break Lfinish
		}
	}
	// Drop capability privileges, if any.
	caps, err := capability.NewPid(0)
	if err != nil {
		return common.NewError("Error retrieving capabilities", "err", err)
	}
	log.Debug("Startup capabilities", "caps", caps)
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)
	caps.Load()
	log.Debug("Cleared capabilities", "caps", caps)
	return nil
}

// setupPosixAddLocal configures a local POSIX(/BSD) socket.
func setupPosixAddLocal(r *Router, idx int, over *overlay.UDP,
	labels prometheus.Labels) (rpkt.HookResult, *common.Error) {
	// Listen on the socket.
	if err := over.Listen(); err != nil {
		return rpkt.HookError, common.NewError("Unable to listen on local socket", "err", err)
	}
	// Find interfaces that use this local address.
	var ifids []spath.IntfID
	for _, intf := range conf.C.Net.IFs {
		if intf.LocAddrIdx == idx {
			ifids = append(ifids, intf.Id)
		}
	}
	// Setup input queue & goroutine
	inQ := make(chan *rpkt.RtrPkt, chanBufSize)
	r.inQs = append(r.inQs, inQ)
	go r.readPosixInput(over.Conn, rpkt.DirLocal, ifids, labels, inQ)
	// Setup output queue & goroutine
	r.locOutQs[idx] = make(rpkt.OutputQueue, chanBufSize)
	go r.posixLocalOutput(r.locOutQs[idx], over.Conn, labels)
	return rpkt.HookFinish, nil
}

// setupPosixAddExt configures a POSIX(/BSD) interface socket.
func setupPosixAddExt(r *Router, intf *netconf.Interface,
	labels prometheus.Labels) (rpkt.HookResult, *common.Error) {
	// Connect to remote address.
	if err := intf.IFAddr.Connect(intf.RemoteAddr); err != nil {
		return rpkt.HookError, common.NewError("Unable to listen on external socket", "err", err)
	}
	// Setup input queue & goroutine
	q := make(chan *rpkt.RtrPkt, chanBufSize)
	r.inQs = append(r.inQs, q)
	go r.readPosixInput(intf.IFAddr.Conn, rpkt.DirExternal, []spath.IntfID{intf.Id}, labels, q)
	// Setup output queue & goroutine
	r.intfOutQs[intf.Id] = make(rpkt.OutputQueue, chanBufSize)
	go r.posixIntfOutput(r.intfOutQs[intf.Id], intf.IFAddr.Conn, labels)
	return rpkt.HookFinish, nil
}
