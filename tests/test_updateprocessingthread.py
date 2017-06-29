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

from base import BaseTestCase, NETWORKS
from invalidroutesreporter import UpdatesProcessingThread

class UpdatesProcessingThread_ExtCommsParsing_TestCase(BaseTestCase):

    def _test_ext_comm(self, val, exp_res):
        res = UpdatesProcessingThread.ext_comms_to_str([val])[0]
        self.assertEqual(res, exp_res)

    def test_ext_comms(self):
        """Extended communities decoding"""
        self._test_ext_comm(144678147958964239, "rt:151515:15")
        self._test_ext_comm(563014378082267, "rt:15:151515")
        self._test_ext_comm(844489354792923, "ro:15:151515")
        self._test_ext_comm(144959622935674895, "ro:151515:15")
        self._test_ext_comm(750597074583562, "rt:43690:10")
        self._test_ext_comm(750597074583652, "rt:43690:100")

class UpdatesProcessingThread_BaseTestCase(BaseTestCase):

    __test__ = False

    def shortDescription(self):
        return self._testMethodDoc

    def setup_thread(self, reject_bgp_comm, reject_reason_pattern,
                     rejected_route_announced_by_pattern=None,
                     networks=NETWORKS):
        self.updates_q = Queue()
        self.alert_q = Queue()

        self.t = UpdatesProcessingThread(self.updates_q, [self.alert_q],
                                         reject_bgp_comm, reject_reason_pattern,
                                         rejected_route_announced_by_pattern,
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
            for comm in ("std", "ext", "lrg"):
                if "{}_comms".format(comm) in alert:
                    del alert["{}_comms".format(comm)]
            alerts.append(alert)

        if exp_results:
            self.maxDiff = None
            self.assertListEqual(alerts, exp_results)
        else:
            return alerts

class UpdatesProcessingThread_CommsMatching_TestCase(UpdatesProcessingThread_BaseTestCase):

    __test__ = True

    RE_PATT_ANNOUNCED_BY_STD = None
    RE_PATT_ANNOUNCED_BY_LRG = None
    RE_PATT_ANNOUNCED_BY_EXT = None

    ANNOUNCED_BY_STD = None
    ANNOUNCED_BY_LRG = None
    ANNOUNCED_BY_EXT = None

    ANNOUNCED_BY_ASN = None
    EXP_RECIPIENTS_ID = ["AS1"]

    def _add_lines_comms_matching(self):
        ann_by_std = [self.ANNOUNCED_BY_STD] if self.ANNOUNCED_BY_STD else []
        ann_by_lrg = [self.ANNOUNCED_BY_LRG] if self.ANNOUNCED_BY_LRG else []
        ann_by_ext = [self.ANNOUNCED_BY_EXT] if self.ANNOUNCED_BY_EXT else []

        # reject comm only
        self.add_line("1", [("192.0.2.11", ["1.0.0.0/8"])],
                      std_comms=ann_by_std + [[65520,0]])
        self.add_line("1", [("192.0.2.11", ["2.0.0.0/8"])],
                      ext_comms=ann_by_ext + [563014378082267])    # rt:15:151515
        self.add_line("1", [("192.0.2.11", ["3.0.0.0/8"])],
                      lrg_comms=ann_by_lrg + [[65520,0,0]])

        # reject comm + reject reason comm
        self.add_line("1", [("192.0.2.11", ["4.0.0.0/8"])],
                      std_comms=ann_by_std + [[65520,0], [65520,15]])
        self.add_line("1", [("192.0.2.11", ["5.0.0.0/8"])],
                      ext_comms=ann_by_ext + [563014378082267, 144678147958964239])    # rt:15:151515, rt:151515:15
        self.add_line("1", [("192.0.2.11", ["6.0.0.0/8"])],
                      lrg_comms=ann_by_lrg + [[65520,0,0], [65520,0,15]])

        # reject reason comm only
        self.add_line("1", [("192.0.2.11", ["7.0.0.0/8"])],
                      std_comms=ann_by_std + [[65520,15]])
        self.add_line("1", [("192.0.2.11", ["8.0.0.0/8"])],
                      ext_comms=ann_by_ext + [144678147958964239])    # rt:15:151515, rt:151515:15
        self.add_line("1", [("192.0.2.11", ["9.0.0.0/8"])],
                      lrg_comms=ann_by_lrg + [[65520,0,15]])

        # rejected route announced by comm only
        self.add_line("1", [("192.0.2.11", ["10.0.0.0/8"])], std_comms=[[43690,10]])
        self.add_line("1", [("192.0.2.11", ["11.0.0.0/8"])], ext_comms=[750597074583562])   # rt:43690:10
        self.add_line("1", [("192.0.2.11", ["12.0.0.0/8"])], lrg_comms=[[43690,0,10]])

        # nothing
        self.add_line("1", [("192.0.2.11", ["255.0.0.0/8"])])

    def test_reject_comm_only_std(self):
        """Reject comm only: std"""
        self.setup_thread("65520:0", None, self.RE_PATT_ANNOUNCED_BY_STD)

        ann_by = self.ANNOUNCED_BY_ASN
        rec_ids = self.EXP_RECIPIENTS_ID

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '1.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': None, 'announced_by': ann_by,
                'as_path': [1]
            },
            {
                'prefix': '4.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': None, 'announced_by': ann_by,
                'as_path': [1]
            }
        ])

    def test_reject_comm_only_lrg(self):
        """Reject comm only: lrg"""
        self.setup_thread("65520:0:0", None, self.RE_PATT_ANNOUNCED_BY_LRG)

        ann_by = self.ANNOUNCED_BY_ASN
        rec_ids = self.EXP_RECIPIENTS_ID

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '3.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': None, 'announced_by': ann_by,
                'as_path': [1]
            },
            {
                'prefix': '6.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': None, 'announced_by': ann_by,
                'as_path': [1]
            }
        ])

    def test_reject_comm_only_ext(self):
        """Reject comm only: ext"""
        self.setup_thread("rt:15:151515", None, self.RE_PATT_ANNOUNCED_BY_EXT)

        ann_by = self.ANNOUNCED_BY_ASN
        rec_ids = self.EXP_RECIPIENTS_ID

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '2.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': None, 'announced_by': ann_by,
                'as_path': [1]
            },
            {
                'prefix': '5.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': None, 'announced_by': ann_by,
                'as_path': [1]
            }
        ])

    def test_reject_comm_and_reason_std(self):
        """Reject comm + reason: std"""
        self.setup_thread("65520:0", "^65520:(\d+)$", self.RE_PATT_ANNOUNCED_BY_STD)

        ann_by = self.ANNOUNCED_BY_ASN
        rec_ids = self.EXP_RECIPIENTS_ID

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '1.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': None, 'announced_by': ann_by,
                'as_path': [1]
            },
            {
                'prefix': '4.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': 15, 'announced_by': ann_by,
                'as_path': [1]
            }
        ])

    def test_reject_comm_and_reason_lrg(self):
        """Reject comm + reason: lrg"""
        self.setup_thread("65520:0:0", "65520:0:(\d+)$", self.RE_PATT_ANNOUNCED_BY_LRG)

        ann_by = self.ANNOUNCED_BY_ASN
        rec_ids = self.EXP_RECIPIENTS_ID

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '3.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': None, 'announced_by': ann_by,
                'as_path': [1]
            },
            {
                'prefix': '6.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': 15, 'announced_by': ann_by,
                'as_path': [1]
            }
        ])

    def test_reject_comm_and_reason_ext(self):
        """Reject comm + reason: ext"""
        self.setup_thread("rt:15:151515", "rt:151515:(\d+)$", self.RE_PATT_ANNOUNCED_BY_EXT)

        ann_by = self.ANNOUNCED_BY_ASN
        rec_ids = self.EXP_RECIPIENTS_ID

        self._add_lines_comms_matching()
        self.process_lines([
            {
                'prefix': '2.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': None, 'announced_by': ann_by,
                'as_path': [1]
            },
            {
                'prefix': '5.0.0.0/8', 'next_hop': '192.0.2.11',
                'recipient_ids': rec_ids, 'reject_reason_code': 15, 'announced_by': ann_by,
                'as_path': [1]
            }
        ])

class UpdatesProcessingThread_CommsMatching_WithAnnouncingASN_TestCase(UpdatesProcessingThread_CommsMatching_TestCase):

    __test__ = True

    RE_PATT_ANNOUNCED_BY_STD = "^43690:(\d+)$"
    RE_PATT_ANNOUNCED_BY_LRG = "^43690:0:(\d+)$"
    RE_PATT_ANNOUNCED_BY_EXT = "^rt:43690:(\d+)$"

    ANNOUNCED_BY_STD = [43690,10]
    ANNOUNCED_BY_LRG = [43690,0,10]
    ANNOUNCED_BY_EXT = 750597074583562

    ANNOUNCED_BY_ASN = 10
    EXP_RECIPIENTS_ID = ["AS1", "AS10"]

    def shortDescription(self):
        return self._testMethodDoc + " (with announcing ASN)"

class UpdatesProcessingThread_CommsMatching_WithAnnouncingASNNotInList_TestCase(UpdatesProcessingThread_CommsMatching_TestCase):

    __test__ = True

    RE_PATT_ANNOUNCED_BY_STD = "^43690:(\d+)$"
    RE_PATT_ANNOUNCED_BY_LRG = "^43690:0:(\d+)$"
    RE_PATT_ANNOUNCED_BY_EXT = "^rt:43690:(\d+)$"

    ANNOUNCED_BY_STD = [43690,100]
    ANNOUNCED_BY_LRG = [43690,0,100]
    ANNOUNCED_BY_EXT = 750597074583652

    ANNOUNCED_BY_ASN = 100
    EXP_RECIPIENTS_ID = ["AS1"]

    def shortDescription(self):
        return self._testMethodDoc + " (with announcing ASN not in networks list)"

class UpdatesProcessingThread_Recipients_TestCase(UpdatesProcessingThread_BaseTestCase):

    __test__ = True

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

    def test_recipients_from_as_path_and_next_hop_different_with_announcing_asn(self):
        """Recipients from AS_PATH and NEXT_HOP (different) with announcing ASN"""
        self.setup_thread("65520:0", None, "^43690:(\d+)$")

        self.add_line("1 11 111", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [43690,10]])
        self.add_line("3", [("192.0.2.23", ["2.0.0.0/8"])], std_comms=[[65520,0], [43690,10]])
        self.recipients_match([["AS1", "AS2", "AS10"], ["AS3", "AS23", "AS10"]])

    def test_recipients_from_as_path_and_next_hop_different_with_announcing_asn_not_in_list(self):
        """Recipients from AS_PATH and NEXT_HOP (different) with announcing ASN not in networks list"""
        self.setup_thread("65520:0", None, "^43690:(\d+)$")

        self.add_line("1 11 111", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [43690,100]])
        self.add_line("3", [("192.0.2.23", ["2.0.0.0/8"])], std_comms=[[65520,0], [43690,100]])
        self.recipients_match([["AS1", "AS2"], ["AS3", "AS23"]])
