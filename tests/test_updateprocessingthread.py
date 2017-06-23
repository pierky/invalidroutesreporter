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

import time
from Queue import Queue, Empty

from base import BaseTestCase
from invalidroutesreporter import UpdatesProcessingThread

NETWORKS = {
    "AS1": {
        "neighbors": ["192.0.2.11", "2001:db8:1:1::11", "192.0.2.12", "2001:db8:1:1::12"]
    },
    "AS2": {
        "neighbors": ["192.0.2.21", "2001:db8:1:1::21"]
    },
    "AS3": {
        "neighbors": ["192.0.2.31", "2001:db8:1:1::31"]
    },
    "AS23" : {
        "neighbors": ["192.0.2.23"]
    }
}

class UpdatesProcessingThreadTestCase(BaseTestCase):

    def setup_thread(self, reject_bgp_comm, reject_reason_pattern,
                     networks=NETWORKS):
        self.updates_q = Queue()
        self.alert_q = Queue()

        self.t = UpdatesProcessingThread(self.updates_q, [self.alert_q],
                                         reject_bgp_comm, reject_reason_pattern,
                                         networks)

    def add_line(self, *args, **kwargs):
        self.updates_q.put(self.build_exabgp_line(*args, **kwargs))

    def process_lines(self, exp_results=None):
        self.t.start()

        for attempts in [1,2,3]:
            if self.updates_q.empty():
                break
            time.sleep(0.3)

        if not self.updates_q.empty():
            self.fail("Queue is not empty")

        self.t.quit_flag = True

        alerts = []
        while True:
            try:
                alert = self.alert_q.get(block=False)
            except Empty:
                break
            if "ts" in alert:
                del alert["ts"]
            alerts.append(alert)

        if exp_results:
            self.assertListEqual(alerts, exp_results)
        else:
            return alerts

    def _test_ext_comm(self, val, exp_res):
        res = UpdatesProcessingThread.ext_comms_to_str([val])[0]
        self.assertEqual(res, exp_res)

    def test_ext_comms(self):
        """Extended communities decoding"""
        self._test_ext_comm(144678147958964239, "rt:151515:15")
        self._test_ext_comm(563014378082267, "rt:15:151515")
        self._test_ext_comm(844489354792923, "ro:15:151515")
        self._test_ext_comm(144959622935674895, "ro:151515:15")

    def _add_lines_comms_matching(self):
        # reject comm only
        self.add_line("1", [("192.0.2.11", ["1.0.0.0/8"])], std_comms=[[65520,0]])
        self.add_line("1", [("192.0.2.11", ["2.0.0.0/8"])], ext_comms=[563014378082267])    # rt:15:151515
        self.add_line("1", [("192.0.2.11", ["3.0.0.0/8"])], lrg_comms=[[65520,0,0]])

        # reject comm + reject reason comm
        self.add_line("1", [("192.0.2.11", ["4.0.0.0/8"])], std_comms=[[65520,0], [65520,15]])
        self.add_line("1", [("192.0.2.11", ["5.0.0.0/8"])], ext_comms=[563014378082267, 144678147958964239])    # rt:15:151515, rt:151515:15
        self.add_line("1", [("192.0.2.11", ["6.0.0.0/8"])], lrg_comms=[[65520,0,0], [65520,0,15]])

        # reject reason comm only
        self.add_line("1", [("192.0.2.11", ["7.0.0.0/8"])], std_comms=[[65520,15]])
        self.add_line("1", [("192.0.2.11", ["8.0.0.0/8"])], ext_comms=[144678147958964239])    # rt:15:151515, rt:151515:15
        self.add_line("1", [("192.0.2.11", ["9.0.0.0/8"])], lrg_comms=[[65520,0,15]])

        # nothing
        self.add_line("1", [("192.0.2.11", ["255.0.0.0/8"])])

    def test_reject_comm_only_std(self):
        """Reject comm only: std"""
        self.setup_thread("65520:0", None)

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '1.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': [], 'std_comms': ['65520:0'], 'lrg_comms': [],
                'recipient_ids': ['AS1'], 'reject_reason_code': None,
                'as_path': [1]
            },
            {
                'prefix': '4.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': [], 'std_comms': ['65520:0', '65520:15'], 'lrg_comms': [],
                'recipient_ids': ['AS1'], 'reject_reason_code': None,
                'as_path': [1]
            }
        ])

    def test_reject_comm_only_lrg(self):
        """Reject comm only: lrg"""
        self.setup_thread("65520:0:0", None)

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '3.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': [], 'std_comms': [], 'lrg_comms': ['65520:0:0'],
                'recipient_ids': ['AS1'], 'reject_reason_code': None,
                'as_path': [1]
            },
            {
                'prefix': '6.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': [], 'std_comms': [], 'lrg_comms': ['65520:0:0', '65520:0:15'],
                'recipient_ids': ['AS1'], 'reject_reason_code': None,
                'as_path': [1]
            }
        ])

    def test_reject_comm_only_ext(self):
        """Reject comm only: ext"""
        self.setup_thread("rt:15:151515", None)

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '2.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': ['rt:15:151515'], 'std_comms': [], 'lrg_comms': [],
                'recipient_ids': ['AS1'], 'reject_reason_code': None,
                'as_path': [1]
            },
            {
                'prefix': '5.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': ['rt:15:151515', 'rt:151515:15'], 'std_comms': [], 'lrg_comms': [],
                'recipient_ids': ['AS1'], 'reject_reason_code': None,
                'as_path': [1]
            }
        ])

    def test_reject_comm_and_reason_std(self):
        """Reject comm + reason: std"""
        self.setup_thread("65520:0", "^65520:(\d+)$")

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '1.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': [], 'std_comms': ['65520:0'], 'lrg_comms': [],
                'recipient_ids': ['AS1'], 'reject_reason_code': None,
                'as_path': [1]
            },
            {
                'prefix': '4.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': [], 'std_comms': ['65520:0', '65520:15'], 'lrg_comms': [],
                'recipient_ids': ['AS1'], 'reject_reason_code': 15,
                'as_path': [1]
            }
        ])

    def test_reject_comm_and_reason_lrg(self):
        """Reject comm + reason: lrg"""
        self.setup_thread("65520:0:0", "65520:0:(\d+)$")

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '3.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': [], 'std_comms': [], 'lrg_comms': ['65520:0:0'],
                'recipient_ids': ['AS1'], 'reject_reason_code': None,
                'as_path': [1]
            },
            {
                'prefix': '6.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': [], 'std_comms': [], 'lrg_comms': ['65520:0:0', '65520:0:15'],
                'recipient_ids': ['AS1'], 'reject_reason_code': 15,
                'as_path': [1]
            }
        ])

    def test_reject_comm_and_reason_ext(self):
        """Reject comm + reason: ext"""
        self.setup_thread("rt:15:151515", "rt:151515:(\d+)$")

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '2.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': ['rt:15:151515'], 'std_comms': [], 'lrg_comms': [],
                'recipient_ids': ['AS1'], 'reject_reason_code': None,
                'as_path': [1]
            },
            {
                'prefix': '5.0.0.0/8', 'next_hop': '192.0.2.11',
                'ext_comms': ['rt:15:151515', 'rt:151515:15'], 'std_comms': [], 'lrg_comms': [],
                'recipient_ids': ['AS1'], 'reject_reason_code': 15,
                'as_path': [1]
            }
        ])

    def _add_lines_recipients_matching(self):
        # match on AS_PATH

        self.add_line("1 2 3", [("192.0.2.11", ["1.0.0.0/8"])], std_comms=[[65520,0]])

    def recipients_match(self, exp_recipient_ids):
        alerts = self.process_lines()
        self.assertEqual(len(alerts), len(exp_recipient_ids))
        for idx in range(len(alerts)):
            self.assertEqual(
                sorted(alerts[idx]["recipient_ids"]),
                sorted(exp_recipient_ids[idx])
            )

    def test_recipients_from_as_path_only(self):
        """Recipients from AS_PATH"""
        self.setup_thread("65520:0", None)

        self.add_line("1 11 111", [("192.0.2.255", ["1.0.0.0/8"])], std_comms=[[65520,0]])
        self.add_line("4 44 444", [("192.0.2.255", ["2.0.0.0/8"])], std_comms=[[65520,0]])
        self.add_line("5 1", [("192.0.2.255", ["3.0.0.0/8"])], std_comms=[[65520,0]])
        self.recipients_match([["AS1"], [], []])

    def test_recipients_from_next_hop_only(self):
        """Recipients from NEXT_HOP"""
        self.setup_thread("65520:0", None)

        self.add_line("4 44 444", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0]])
        self.add_line("5 1", [("192.0.2.255", ["2.0.0.0/8"])], std_comms=[[65520,0]])
        self.add_line("6", [("192.0.2.23", ["2.0.0.0/8"])], std_comms=[[65520,0]])
        self.recipients_match([["AS2"], [], ["AS23"]])

    def test_recipients_from_as_path_and_next_hop_same(self):
        """Recipients from AS_PATH and NEXT_HOP (the same)"""
        self.setup_thread("65520:0", None)

        self.add_line("1 11 111", [("192.0.2.11", ["1.0.0.0/8"])], std_comms=[[65520,0]])
        self.add_line("2", [("192.0.2.21", ["2.0.0.0/8"])], std_comms=[[65520,0]])
        self.recipients_match([["AS1"], ["AS2"]])

    def test_recipients_from_as_path_and_next_hop_different(self):
        """Recipients from AS_PATH and NEXT_HOP (different)"""
        self.setup_thread("65520:0", None)

        self.add_line("1 11 111", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0]])
        self.add_line("3", [("192.0.2.23", ["2.0.0.0/8"])], std_comms=[[65520,0]])
        self.recipients_match([["AS1", "AS2"], ["AS3", "AS23"]])
