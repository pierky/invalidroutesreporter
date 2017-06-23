# Copyright (C) 2017 Pier Carlo Chiodi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import logging
import unittest

class CaptureLog(logging.Handler):

    def __init__(self, *args, **kwargs):
        self.reset_messages()
        super(CaptureLog, self).__init__(*args, **kwargs)

    def reset_messages(self):
        self.msgs = []

    def emit(self, record):
        self.acquire()
        try:
            if record.levelname.lower() == "error":
                self.msgs.append(record.getMessage())
        finally:
            self.release()
    
    def reset(self):
        self.acquire()
        try:
            self._reset_messages()
        finally:
            self.release()

class BaseTestCase(unittest.TestCase):

    def _setUp(self):
        pass

    def setUp(self):
        self._capture_log()
        self._setUp()

    def _tearDown(self):
        pass

    def tearDown(self):
        self._tearDown()

    def _capture_log(self):
        logger = logging.getLogger()
        self.logger_handler = CaptureLog(level="DEBUG")
        logger.addHandler(self.logger_handler)

        self.logger_handler.reset_messages()

    def build_exabgp_line(self, as_path, nexthop_prefixes,
                          std_comms=None, lrg_comms=None, ext_comms=None):

        res = {
            "exabgp": 1,
            "type": "update",
            "neighbor": {
                "message": {
                    "update": {
                        "attribute": {
                        },
                        "announce": {
                            "ipv{} unicast".format(6 if ":" in nexthop_prefixes[0][0] else 4): {
                                next_hop: prefixes for next_hop, prefixes in nexthop_prefixes
                            }
                        }
                    }
                }
            }
        }
        attribute = res["neighbor"]["message"]["update"]["attribute"]
        if isinstance(as_path, str):
            attribute["as-path"] = map(int, as_path.split(" "))
        else:
            attribute["as-path"] = as_path
        if std_comms:
            attribute["community"] = std_comms
        if lrg_comms:
            attribute["large-community"] = lrg_comms
        if ext_comms:
            attribute["extended-community"] = ext_comms
        return res
