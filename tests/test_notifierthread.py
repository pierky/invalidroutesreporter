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
from StringIO import StringIO
import time
from Queue import Queue, Empty
import re

from base import BaseTestCase, NETWORKS
from invalidroutesreporter import UpdatesProcessingThread, NotifierThread, \
                                  EMailNotifierThread, LoggerThread

class FakeNotifierThread(NotifierThread):

    def __init__(self, out_q, *args, **kwargs):
        super(FakeNotifierThread, self).__init__(*args, **kwargs)

        self.out_q = out_q

    def _flush_recipient(self, recipient):
        self.out_q.put({
            "ts": int(time.time()),
            "recipient": copy.deepcopy(recipient)
        })

class FakeEMailNotifierThread(EMailNotifierThread):

    def __init__(self, out_q, *args, **kwargs):
        super(FakeEMailNotifierThread, self).__init__(*args, **kwargs)

        self.out_q = out_q

    def _send_email(self, from_addr, to_addrs, msg):
        self.out_q.put({
            "from_addr": copy.deepcopy(from_addr),
            "to_addrs": copy.deepcopy(to_addrs),
            "msg": copy.deepcopy(msg)
        })

class FakeLoggerThread(LoggerThread):

    def __init__(self, out_q, *args, **kwargs):
        super(FakeLoggerThread, self).__init__(*args, **kwargs)

        self.out_q = out_q

    def _open_file(self):
        return True

    def _write_to_file(self, msg):
        self.out_q.put({
            "msg": msg
        })

class NotifierThreadBaseTestCase(BaseTestCase):

    __test__ = False

    NOTIFIER_CLASS = None

    def _setUp(self):
        self.min_wait = 0
        self.max_wait = 0
        self.max_routes = 1
        self.recipients = {"*": {}}

        self.t = None
        self.n = None

    def _tearDown(self):
        if self.t:
            self.t.quit_flag = True
        if self.n:
            self.n.quit_flag = True

    def setup_thread(self, alerter_cfg=None, announced_by_pattern=None):
        default_alerter_cfg = {
            "min_wait": self.min_wait,
            "max_wait": self.max_wait,
            "max_routes": self.max_routes,
            "recipients": self.recipients
        }

        if not alerter_cfg:
            used_alerter_cfg = default_alerter_cfg
        else:
            used_alerter_cfg = alerter_cfg.copy()
            for k in ("min_wait", "max_wait", "max_routes"):
                used_alerter_cfg[k] = default_alerter_cfg[k]

        self.updates_q = Queue()
        self.alert_q = Queue()

        self.t = UpdatesProcessingThread(self.updates_q, [self.alert_q],
                                         "65520:0", "^65520:(\d+)$",
                                         announced_by_pattern,
                                         NETWORKS)

        self.out_q = Queue()

        reject_reasons = None

        notifier_class = self.NOTIFIER_CLASS
        self.n = notifier_class(self.out_q, self.alert_q,
                                used_alerter_cfg,
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

class NotifierThreadTestCase(NotifierThreadBaseTestCase):

    __test__ = True

    NOTIFIER_CLASS = FakeNotifierThread

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

class EMailNotifierThreadTestCase(NotifierThreadBaseTestCase):

    __test__ = True

    NOTIFIER_CLASS = FakeEMailNotifierThread

    ALERTER_CFG = {
        "host": "smtp.localhost",
        "from_addr": "rs@acme-ix.tld",
        "template_file": StringIO("Test\n{routes_list}"),
        "port": 25,
        "username": "u",
        "password": "p",
        "subject": "Invalid routes",
        "recipients": {
            "*": {
                "info": {
                    "email": "noc@acme-ix.tld"
                }
            }
        }
    }

    def test_email_config(self):
        """EMail notifier: config"""

        cfg = copy.deepcopy(self.ALERTER_CFG)
        self.setup_thread(alerter_cfg=cfg)

    def test_email_config_host(self):
        """EMail notifier: config, missing host"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        del cfg["host"]
        with self.assertRaisesRegexp(ValueError, "missing 'host' parameter"):
            self.setup_thread(alerter_cfg=cfg)

    def test_email_config_from_addr(self):
        """EMail notifier: config, missing from_addr"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        del cfg["from_addr"]
        with self.assertRaisesRegexp(ValueError, "missing 'from_addr' parameter"):
            self.setup_thread(alerter_cfg=cfg)

    def test_email_config_template_file(self):
        """EMail notifier: config, missing template_file"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        del cfg["template_file"]
        with self.assertRaisesRegexp(ValueError, "missing 'template_file' parameter"):
            self.setup_thread(alerter_cfg=cfg)

    def test_email_config_optional_attrs(self):
        """EMail notifier: config, optional attrs"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        del cfg["port"]
        del cfg["username"]
        del cfg["password"]
        del cfg["subject"]
        self.setup_thread(alerter_cfg=cfg)

    def test_email_config_recipients(self):
        """EMail notifier: config, bad recipients"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        del cfg["recipients"]["*"]["info"]["email"]
        with self.assertRaisesRegexp(ValueError, "Error in the configuration of recipient '\*': missing 'email'."):
            self.setup_thread(alerter_cfg=cfg)

    def test_email_no_announcing_asn(self):
        """EMail notifier: alert"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        self.setup_thread(alerter_cfg=cfg)

        self.add_line("1", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        msg = alert["msg"]
        self.assertIn("From: rs@acme-ix.tld", msg)
        self.assertIn("To: noc@acme-ix.tld", msg)
        patt = re.compile("\n\n"
                          "Test\n"
                          "prefix:\s+1.0.0.0/8\n"
                          " - AS_PATH:\s+1\n"
                          " - NEXT_HOP:\s+192.0.2.21\n"
                          " - reject reason:\s+Reject reason code 1\n$")
        self.assertTrue(patt.search(msg) is not None)
        self.assertEqual(alert["from_addr"], "rs@acme-ix.tld")
        self.assertEqual(alert["to_addrs"], ["noc@acme-ix.tld"])

    def test_email_with_announcing_asn(self):
        """EMail notifier: alert (with announcing ASN)"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        self.setup_thread(alerter_cfg=cfg, announced_by_pattern="^65521:(\d+)$")

        self.add_line("1", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1], [65521,10]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        msg = alert["msg"]
        patt = re.compile("\n\n"
                          "Test\n"
                          "prefix:\s+1.0.0.0/8\n"
                          " - AS_PATH:\s+1\n"
                          " - NEXT_HOP:\s+192.0.2.21\n"
                          " - reject reason:\s+Reject reason code 1\n"
                          " - announced by:\s10\n$")
        self.assertTrue(patt.search(msg) is not None)

    def test_email_with_announcing_asn_not_in_list(self):
        """EMail notifier: alert (with announcing ASN not in networks list)"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        self.setup_thread(alerter_cfg=cfg, announced_by_pattern="^65521:(\d+)$")

        self.add_line("1", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1], [65521,100]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        msg = alert["msg"]
        patt = re.compile("\n\n"
                          "Test\n"
                          "prefix:\s+1.0.0.0/8\n"
                          " - AS_PATH:\s+1\n"
                          " - NEXT_HOP:\s+192.0.2.21\n"
                          " - reject reason:\s+Reject reason code 1\n"
                          " - announced by:\s100\n$")
        self.assertTrue(patt.search(msg) is not None)

class LoggerThreadTestCase(NotifierThreadBaseTestCase):

    __test__ = True

    NOTIFIER_CLASS = FakeLoggerThread

    ALERTER_CFG = {
        "path": "/tmp/log",
        "append": False,
        "template": "{id},{prefix},{as_path},{next_hop},{reject_reason_code},{reject_reason},{announced_by}",
        "recipients": {
            "*": {
            }
        }
    }

    def test_logger_config(self):
        """Logger: config"""

        cfg = copy.deepcopy(self.ALERTER_CFG)
        self.setup_thread(alerter_cfg=cfg)

    def test_logger_config_path(self):
        """Logger: config, missing path"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        del cfg["path"]
        with self.assertRaisesRegexp(ValueError, "missing 'path' parameter"):
            self.setup_thread(alerter_cfg=cfg)

    def test_logger_no_announcing_asn(self):
        """Logger: alert"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        self.setup_thread(alerter_cfg=cfg)

        self.add_line("1 2 3", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        msg = alert["msg"]
        self.assertEqual(msg, "*,1.0.0.0/8,1 2 3,192.0.2.21,1,Reject reason code 1,\n")

    def test_logger_with_announcing_asn(self):
        """Logger: alert (with announcing ASN)"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        self.setup_thread(alerter_cfg=cfg, announced_by_pattern="^65521:(\d+)$")

        self.add_line("1 2 3", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1], [65521,10]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        msg = alert["msg"]
        self.assertEqual(msg, "*,1.0.0.0/8,1 2 3,192.0.2.21,1,Reject reason code 1,10\n")

    def test_logger_with_announcing_asn_not_in_list(self):
        """Logger: alert (with announcing ASN not in networks list)"""
        cfg = copy.deepcopy(self.ALERTER_CFG)
        self.setup_thread(alerter_cfg=cfg, announced_by_pattern="^65521:(\d+)$")

        self.add_line("1 2 3", [("192.0.2.21", ["1.0.0.0/8"])], std_comms=[[65520,0], [65520,1], [65521,100]])
        alerts = self.process_lines()

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        msg = alert["msg"]
        self.assertEqual(msg, "*,1.0.0.0/8,1 2 3,192.0.2.21,1,Reject reason code 1,100\n")
