#!/usr/bin/python3
# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`pktgen` --- SCION packet generator
===========================================
"""
# Stdlib
import argparse
import logging
import os
import time

# SCION
from endhost.sciond import SCIOND_API_SOCKDIR
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.socket import UDPSocket
from test.integration.base_cli_srv import (
    TestClientBase,
    start_sciond,
)


class PktGen(TestClientBase):
    def run(self, count):
        self.sent = 0
        spkt = self._build_pkt()
        raw = spkt.pack()
        next_hop, port = self.sd.get_first_hop(spkt)
        assert next_hop is not None
        logging.debug("Sending (via %s:%s):\n%s", next_hop, port, spkt)
        while True:
            if count > 0 and self.sent >= count:
                break
            self.sock.send(raw, (str(next_hop), port))
            self.sent += 1
        self._shutdown()

    def _create_socket(self, addr):
        return UDPSocket(bind=(str(addr.host), 0, ""),
                         addr_type=addr.host.TYPE)

    def _create_payload(self, spkt):
        data = b"ping " + self.data
        pld_len = self.path.mtu - spkt.cmn_hdr.hdr_len - len(spkt.l4_hdr)
        return self._gen_max_pld(data, pld_len)

    def _gen_max_pld(self, data, pld_len):
        padding = pld_len - len(data)
        return PayloadRaw(data + bytes(padding))

    def _handle_response(self, _):
        raise NotImplementedError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', default="INFO",
                        help='Console logging level (Default: %(default)s)')
    parser.add_argument('-c', '--count', default=1, type=int,
                        help='Number of packets to send. 0 means unlimited.')
    parser.add_argument('src_ia', help='Src ISD-AS')
    parser.add_argument('src_addr', help='Src IP')
    parser.add_argument('dst_ia', help='Dst ISD-AS')
    parser.add_argument('dst_addr', help='Dst IP')
    args = parser.parse_args()
    init_logging("logs/pktgen", console_level=args.loglevel)
    src = SCIONAddr.from_values(ISD_AS(args.src_ia),
                                haddr_parse_interface(args.src_addr))
    dst = SCIONAddr.from_values(ISD_AS(args.dst_ia),
                                haddr_parse_interface(args.dst_addr))
    api_path = "%spktgen_%s_%s.sock" % (
        SCIOND_API_SOCKDIR, src.isd_as, os.getpid())
    sciond = start_sciond(src, api=True, api_addr=api_path)
    gen = PktGen(sciond, b"data", "finished", src, dst, 3000)
    start = time.time()
    try:
        gen.run(args.count)
    except KeyboardInterrupt:
        pass
    total = time.time() - start
    logging.info("Sent %d packets in %.3fs (%.3fs pps)",
                 gen.sent, total, gen.sent/total)
    sciond.stop()

if __name__ == "__main__":
    main_wrapper(main)
