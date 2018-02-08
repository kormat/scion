# Copyright 2018 ETH Zurich
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
:mod:`rudp` --- Reliable UDP/SCION implementation.
==================================================
"""
# Stdlib
import struct

# SCION
from lib.packet.packet_base import PayloadRaw


class RUDPHdr(object):
    LEN = 8
    FLAG_NONE = 0x0
    FLAG_NEED_ACK = 0x1
    FLAG_ACK = 0x2

    def __init__(self, raw=None):
        self.flags = 0
        self.id = b""
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        self.flags, self.id = struct.unpack("!b7s")

    def is_ack(self):
        return self.flags & self.FLAG_ACK

    def is_need_ack(self):
        return self.flags & self.FLAG_NEED_ACK

    def ack_pld(self):
        return PayloadRaw(struct.pack("!b7s", self.FLAG_ACK, self.id))
