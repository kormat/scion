# Copyright 2017 ETH Zurich
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


import tracemalloc
import logging


def profile_start():
    tracemalloc.start()


def profile_log_stats(n=10):
    s = ["Memory stats"]
    for stat in profile_stats()[:n]:
        s.append(str(stat))
    logging.debug("\n  ".join(s))


def profile_stats():
    snapshot = tracemalloc.take_snapshot()
    return snapshot.statistics('lineno')
