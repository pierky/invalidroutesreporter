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

import copy
from pprint import pprint
import time
from Queue import Queue, Empty

from base import BaseTestCase
from invalidroutesreporter import UpdatesProcessingThread, NotifierThread

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

class FakeNotifierThread(NotifierThread):

    def __init__(self, out_q, *args, **kwargs):
        super(FakeNotifierThread, self).__init__(*args, **kwargs)

        self.out_q = out_q

    def _flush_recipient(self, recipient):
        self.out_q.put({
            "ts": int(time.time()),
            "recipient": copy.deepcopy(recipient)
        })

class NotifierThreadTestCase(BaseTestCase):

    def _setUp(self):
        self.min_wait = 0
        self.max_wait = 0
        self.max_routes = 1
        self.recipients = {"*": {}}

    def _tearDown(self):
        self.t.quit_flag = True
        self.n.quit_flag = True

    def setup_thread(self, alerter_cfg=None):
        if not alerter_cfg:
            default_alerter_cfg = {
                "min_wait": self.min_wait,
                "max_wait": self.max_wait,
                "max_routes": self.max_routes,
                "recipients": self.recipients
            }

        self.updates_q = Queue()
        self.alert_q = Queue()

        self.t = UpdatesProcessingThread(self.updates_q, [self.alert_q],
                                         "65520:0", "^65520:(\d+)$",
                                         NETWORKS)

        self.out_q = Queue()

        reject_reasons = None

        self.n = FakeNotifierThread(self.out_q, self.alert_q,
                                    alerter_cfg or default_alerter_cfg,
                                    reject_reasons)

        self.n.start()
        self.t.start()

    def add_line(self, *args, **kwargs):
        self.updates_q.put(self.build_exabgp_line(*args, **kwargs))

    def process_lines(self):
        for attempts in [1,2,3]:
            if self.updates_q.empty():
                break
            time.sleep(0.1)

        if not self.updates_q.empty():
            self.fail("Queue is not empty")

        time.sleep(0.2)

        alerts = []
        while True:
            try:
                alert = self.out_q.get(block=False)
            except Empty:
                break
            alerts.append(alert)

        return alerts

    def test_1_alert_1_route(self):
        """Notifier: 1 alert, 1 route"""

        self.setup_thread()

        self.add_line("1", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0]["recipient"]["routes"]), 1)
        self.assertEqual(alerts[0]["recipient"]["routes"][0]["prefix"], "1.0.0.0/8")
        self.assertEqual(
            sorted(alerts[0]["recipient"]["routes"][0]["recipient_ids"]),
            sorted(["AS1", "AS2"])
        )

    def test_1_alert_2_routes(self):
        """Notifier: 1 alert, 2 routes"""

        self.max_routes = 2
        self.setup_thread()

        self.add_line("1", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        self.add_line("1", [("192.0.2.21", ["2.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0]["recipient"]["routes"]), 2)
        self.assertEqual(alerts[0]["recipient"]["routes"][0]["prefix"], "1.0.0.0/8")
        self.assertEqual(alerts[0]["recipient"]["routes"][1]["prefix"], "2.0.0.0/8")

    def test_2_alerts_2_routes(self):
        """Notifier: 2 alerts, 2 routes"""

        self.setup_thread()

        self.add_line("1", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        self.add_line("1", [("192.0.2.21", ["2.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 2)
        self.assertEqual(len(alerts[0]["recipient"]["routes"]), 1)
        self.assertEqual(len(alerts[1]["recipient"]["routes"]), 1)
        self.assertEqual(alerts[0]["recipient"]["routes"][0]["prefix"], "1.0.0.0/8")
        self.assertEqual(alerts[1]["recipient"]["routes"][0]["prefix"], "2.0.0.0/8")

    def test_1_alerts_1_discarded_routes(self):
        """Notifier: 1 alert, 1 discarded route (min_wait)"""

        self.min_wait = 3
        self.setup_thread()

        self.add_line("1", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        time.sleep(1)
        self.add_line("1", [("192.0.2.21", ["2.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        self.add_line("1", [("192.0.2.21", ["3.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0]["recipient"]["routes"]), 1)
        self.assertEqual(alerts[0]["recipient"]["routes"][0]["prefix"], "1.0.0.0/8")

        time.sleep(3)
        alerts = self.process_lines()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0]["recipient"]["routes"]), 1)
        self.assertEqual(alerts[0]["recipient"]["routes"][0]["prefix"], "2.0.0.0/8")

    def test_2_alerts_1_route_min_wait(self):
        """Notifier: 2 alerts, 1 route (min_wait)"""

        self.min_wait = 2
        self.setup_thread()

        self.add_line("1", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        time.sleep(2.2)
        self.add_line("1", [("192.0.2.21", ["2.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        time.sleep(2.2)
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 2)
        self.assertEqual(len(alerts[0]["recipient"]["routes"]), 1)
        self.assertEqual(len(alerts[1]["recipient"]["routes"]), 1)
        self.assertEqual(alerts[0]["recipient"]["routes"][0]["prefix"], "1.0.0.0/8")
        self.assertEqual(alerts[1]["recipient"]["routes"][0]["prefix"], "2.0.0.0/8")
        self.assertGreaterEqual(alerts[1]["ts"] - alerts[0]["ts"], 2)

    def test_1_alert_2_routes_max_wait(self):
        """Notifier: 1 alert, 2 routes (max_wait)"""

        self.max_wait = 2
        self.max_routes = 3
        self.setup_thread()

        self.add_line("1", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        self.add_line("1", [("192.0.2.21", ["2.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        time.sleep(2)
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0]["recipient"]["routes"]), 2)
        self.assertEqual(alerts[0]["recipient"]["routes"][0]["prefix"], "1.0.0.0/8")
        self.assertEqual(alerts[0]["recipient"]["routes"][1]["prefix"], "2.0.0.0/8")
