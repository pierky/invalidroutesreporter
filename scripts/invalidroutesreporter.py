#!/usr/bin/env python

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

import argparse
import copy
from datetime import datetime
from email.mime.text import MIMEText
import json
import logging
from logging.config import fileConfig, dictConfig
from Queue import Queue, Empty, Full
import re
import smtplib
from StringIO import StringIO
import struct
import sys
import threading
import time

DEFAULT_REJECT_COMMUNITY_PATTERN = "65520:0"
DEFAULT_REJECT_REASON_COMMUNITY_PATTERN = "^65520:(\d+)$"

__version__ = "0.2.0"
COPYRIGHT_YEAR = 2017

class UpdatesProcessingThread(threading.Thread):

    def __init__(self, updates_q, alerts_queues,
                 reject_comm, reject_reason_comm_pattern,
                 rejected_route_announced_by_pattern,
                 peer_asn_only,
                 networks_cfg):
        threading.Thread.__init__(self)

        self.name = "MessagesProcessing"

        self.updates_q = updates_q
        self.alerts_queues = alerts_queues

        self.reject_comm = reject_comm
        if reject_reason_comm_pattern:
            self.reject_reason_comm_pattern = re.compile(reject_reason_comm_pattern)
        else:
            self.reject_reason_comm_pattern = None

        if rejected_route_announced_by_pattern:
            self.rejected_route_announced_by_pattern = re.compile(rejected_route_announced_by_pattern)
        else:
            self.rejected_route_announced_by_pattern = None

        self.peer_asn_only = peer_asn_only

        self.networks_cfg = networks_cfg

        self.quit_flag = False

    def reject_comm_found(self, std_comms, lrg_comms, ext_comms):
        for fmt in (std_comms, lrg_comms, ext_comms):
            if not fmt or len(fmt) == 0:
                continue

            for comm in fmt:
                if comm == self.reject_comm:
                    return True
        return False

    def _extract_val_from_comm(self, std_comms, lrg_comms, ext_comms, re_pattern):
        for fmt in (std_comms, lrg_comms, ext_comms):
            if not fmt or len(fmt) == 0:
                continue

            for comm in fmt:
                if comm == self.reject_comm:
                    continue

                match = re_pattern.match(comm)

                if match:
                    return int(match.group(1))

    def get_reject_reason(self, std_comms, lrg_comms, ext_comms):
        return self._extract_val_from_comm(std_comms, lrg_comms, ext_comms,
                                           self.reject_reason_comm_pattern)

    def get_peer_asn(self, std_comms, lrg_comms, ext_comms):
        if not self.rejected_route_announced_by_pattern:
            return

        return self._extract_val_from_comm(std_comms, lrg_comms, ext_comms,
                                           self.rejected_route_announced_by_pattern)

    def get_recipient_ids(self, as_path, next_hop):
        ids = []

        if as_path:
            asn = "AS{}".format(as_path[0])
            if asn in self.networks_cfg:
                ids.append(asn)

        if next_hop:
            for asn in self.networks_cfg:
                if "neighbors" in self.networks_cfg[asn]:
                    neighbors = self.networks_cfg[asn]["neighbors"]
                    if next_hop in [n.lower() for n in neighbors]:
                        ids.append(asn)

        return list(set(ids))

    def process_route(self, prefix, next_hop, as_path, std_comms, lrg_comms, ext_comms):
        if not self.reject_comm_found(std_comms, lrg_comms, ext_comms):
            return

        reject_reason = None
        if self.reject_reason_comm_pattern:
            reject_reason = self.get_reject_reason(std_comms, lrg_comms, ext_comms)

        rejected_route_announced_by_asn = None
        if self.rejected_route_announced_by_pattern:
            rejected_route_announced_by_asn = \
                self.get_peer_asn(std_comms, lrg_comms, ext_comms)

        if self.peer_asn_only:
            recipient_ids = []
        else:
            recipient_ids = self.get_recipient_ids(as_path, next_hop)

        if rejected_route_announced_by_asn:
            asn = "AS{}".format(rejected_route_announced_by_asn)
            if asn in self.networks_cfg:
                recipient_ids.append(asn)

        route = {
            "ts": int(time.time()),
            "prefix": prefix,
            "next_hop": next_hop,
            "as_path": as_path,
            "std_comms": std_comms,
            "lrg_comms": lrg_comms,
            "ext_comms": ext_comms,
            "reject_reason_code": reject_reason,
            "announced_by": rejected_route_announced_by_asn,
            "recipient_ids": recipient_ids
        }
        logging.debug("Enqueuing route: {}".format(str(route)))
        for alerts_q in self.alerts_queues:
            alerts_q.put(copy.deepcopy(route))

    @staticmethod
    def std_comms_to_str(lst):
        if not lst or len(lst) == 0:
            return []
        for comm in lst:
            try:
                if len(comm) != 2:
                    raise ValueError()
                if not all(isinstance(part, int) for part in comm):
                    raise ValueError()
            except ValueError:
                logging.error("Invalid standard community: {}; "
                              "[x, y] expected".format(comm))
        return [":".join(map(str, parts)) for parts in lst]

    @staticmethod
    def lrg_comms_to_str(lst):
        if not lst or len(lst) == 0:
            return []
        for comm in lst:
            try:
                if len(lst) != 3:
                    raise ValueError()
                if not all(isinstance(part, int) for part in comm):
                    raise ValueError()
            except ValueError:
                logging.error("Invalid large community: {}; "
                              "[x, y, z] expected".format(comm))
        return [":".join(map(str, parts)) for parts in lst]

    @staticmethod
    def ext_comms_to_str(lst):
        if not lst or len(lst) == 0:
            return []
        res = []
        for comm in lst:
            if not isinstance(comm, int):
                logging.error("Invalid extended community: {}; "
                              "[x] expected".format(comm))
            buff = struct.pack("!Q", comm)
            type_h, type_l = struct.unpack_from("!BB", buff, 0)

            kind, part1, part2 = (None, None, None)
            fmt = None

            if type_h in [0x00, 0x40]:
                # 2 + 4
                fmt = "!HI"
            elif type_h in [0x01, 0x41]:
                # 4 + 2
                fmt = "!IH"
            elif type_h in [0x02, 0x42]:
                # 4 + 2
                fmt = "!IH"
            else:
                logging.error("Unhandled extended community "
                              "type for {}: {}".format(comm, type_h))

            if type_l == 0x02:
                kind = "rt"
            elif type_l == 0x03:
                kind = "ro"
            else:
                logging.error("Unhandled extended community "
                              "subtype for {}: {}".format(comm, type_l))

            if kind and fmt:
                part1, part2 = struct.unpack_from(fmt, buff, 2)
                res.append("{}:{}:{}".format(kind, part1, part2))

        return res

    def run(self):
        while True:
            try:
                obj = self.updates_q.get(block=True, timeout=0.5)
                update = obj["neighbor"]["message"]["update"]

                as_path = None
                std_comms = None
                lrg_comms = None
                ext_comms = None
                next_hop = None
                if "attribute" in update:
                    attribute = update["attribute"]
                    as_path = attribute.get("as-path")
                    std_comms = attribute.get("community")
                    lrg_comms = attribute.get("large-community")
                    ext_comms = attribute.get("extended-community")

                if "announce" in update:
                    announce = update["announce"]
                    for afi_safi in announce:
                        if afi_safi not in ("ipv4 unicast", "ipv6 unicast"):
                            continue
                        for next_hop in announce[afi_safi]:
                            for prefix in announce[afi_safi][next_hop]:
                                self.process_route(prefix, next_hop, as_path,
                                                   self.std_comms_to_str(std_comms),
                                                   self.lrg_comms_to_str(lrg_comms),
                                                   self.ext_comms_to_str(ext_comms))

                self.updates_q.task_done()
            except Empty:
                if self.quit_flag:
                    logging.debug("Quitting collector")
                    return

class NotifierThread(threading.Thread):

    THREAD_TYPE = "Notifier"

    def __init__(self, alerts_q, alerter_cfg, reject_reasons):
        threading.Thread.__init__(self)

        self.name = self.THREAD_TYPE

        self.alerts_q = alerts_q
        self.quit_flag = False

        self.cfg = alerter_cfg

        self.reject_reasons = reject_reasons

        self.data = {}
        if not "recipients" in self.cfg:
            raise ValueError("Missing 'recipients'")

        for recipient_id in self.cfg["recipients"]:
            recipient = self.cfg["recipients"][recipient_id]

            self.data[str(recipient_id)] = {
                "id": recipient_id,
                "config": {
                    "info": recipient["info"] if "info" in recipient else None,
                    "max_routes": int(
                        recipient.get("max_routes",
                                      self.cfg.get("max_routes", 30))
                    ),
                    "max_wait": int(
                        recipient.get("max_wait",
                                      self.cfg.get("max_wait", 900))
                    ),
                    "min_wait": int(
                        recipient.get("min_wait",
                                      self.cfg.get("min_wait", 300))
                    )
                },
                "last_flush": None,
                "startup": int(time.time()),
                "routes": []
            }

        self.validate_config()

    def validate_config(self):
        pass

    def process_alert(self, route):
        recipients = list(set(route["recipient_ids"]))

        logging.debug("Processing alert for {}, recipients {}".format(
            str(route), str(recipients)
        ))

        if "*" in self.data:
            recipients.append("*")

        for recipient_id in recipients:
            if not recipient_id in self.data:
                continue

            recipient = self.data[recipient_id]

            if len(recipient["routes"]) < recipient["config"]["max_routes"]:
                recipient["routes"].append(route)
            else:
                logging.debug("Discarding route {} for {}: buffer full ".format(
                    route["prefix"], recipient_id
                ))

    def _flush_recipient(self, recipient):
        raise NotImplementedError()

    def flush_recipient(self, recipient):
        ts = int(time.time())

        self._flush_recipient(recipient)

        recipient["last_flush"] = ts
        recipient["routes"] = []

    def flush(self):
        ts = int(time.time())
        logging.debug("Flush {}".format(ts))
        for recipient_id in self.data:
            recipient = self.data[recipient_id]

            routes_cnt = len(recipient["routes"])

            if routes_cnt == 0:
                continue

            last_time = recipient["last_flush"] or 0
            if recipient["config"]["min_wait"]:
                if last_time + recipient["config"]["min_wait"] > ts:
                    logging.debug("Skipping {} for min_wait ({}, {})".format(
                        recipient_id, recipient["config"]["min_wait"], last_time
                    ))
                    continue

            if routes_cnt >= recipient["config"]["max_routes"]:
                logging.debug("Flushing {} because routes_cnt ({}) >= max_routes ({})".format(
                    recipient_id, routes_cnt, recipient["config"]["max_routes"]
                ))
                self.flush_recipient(recipient)
                continue

            last_time = recipient["last_flush"] or recipient["startup"]
            if recipient["config"]["max_wait"]:
                if last_time + recipient["config"]["max_wait"] <= ts:
                    logging.debug("Flushing {} because max_wait ({}, {})".format(
                        recipient_id, recipient["config"]["max_wait"], last_time
                    ))
                    self.flush_recipient(recipient)
                    continue

    def get_reject_reason_descr(self, reason_code):
        if reason_code:
            if self.reject_reasons:
                if str(reason_code) in self.reject_reasons:
                    return self.reject_reasons[str(reason_code)]
                else:
                    return "Unknown reject reason code {}".format(reason_code)
            else:
                return "Reject reason code {}".format(reason_code)
        return "Reject reason code not found"

    def run(self):
        while True:
            try:
                alert = self.alerts_q.get(block=True, timeout=1)
                self.process_alert(alert)
                self.alerts_q.task_done()
            except Empty:
                if self.quit_flag:
                    logging.debug("Quitting notifier")
                    return
            self.flush()

class EMailNotifierThread(NotifierThread):

    THREAD_TYPE = "EMail"

    def __init__(self, *args, **kwargs):
        super(EMailNotifierThread, self).__init__(*args, **kwargs)

        self.smtp_connection = None

    def validate_config(self):
        try:
            if not "host" in self.cfg:
                raise ValueError("missing 'host' parameter")
            self.host = self.cfg["host"]

            if not "from_addr" in self.cfg:
                raise ValueError("missing 'from_addr' parameter")
            self.from_addr = self.cfg["from_addr"]

            if not "template_file" in self.cfg:
                raise ValueError("missing 'template_file' parameter")
            self.template_file = self.cfg["template_file"]

            self.port = int(self.cfg.get("port", 25))
            self.username = self.cfg.get("username", None)
            self.password = self.cfg.get("password", None)
            self.subject = self.cfg.get("subject", "Bad routes received!")

            if isinstance(self.template_file, StringIO):
                self.template = self.template_file.read()
            else:
                with open(self.template_file, "r") as f:
                    self.template = f.read()
        except ValueError as e:
            raise ValueError(
                "Error in the configuration of the alerter: {}".format(
                    str(e)
                )
            )

        for recipient_id in self.data:
            recipient = self.data[recipient_id]
            try:
                if "config" not in recipient:
                    raise ValueError("missing 'config'.")
                if "info" not in recipient["config"]:
                    raise ValueError("missing 'info'.")
                if "email" not in recipient["config"]["info"]:
                    raise ValueError("missing 'email'.")
            except ValueError as e:
                raise ValueError(
                    "Error in the configuration of recipient '{}': "
                    "{}".format(
                        recipient_id, str(e)
                    )
                )

    def _format_list_of_routes(self, routes):
        res = ""
        for route in routes:
            if res:
                res += "\n"
            res += "prefix:      {}\n".format(route["prefix"])
            res += " - AS_PATH:  {}\n".format(" ".join(map(str, route["as_path"])))
            res += " - NEXT_HOP: {}\n".format(route["next_hop"])
            res += " - reject reason: {}\n".format(
                self.get_reject_reason_descr(route["reject_reason_code"])
            )
            if route["announced_by"]:
                res += " - announced by: {}\n".format(route["announced_by"])
        return res

    def _connect_smtp(self, force=False):
        if self.smtp_connection is not None and not force:
            return True

        try:
            logging.debug("Connecting to SMTP server {}:{}".format(
                self.host, self.port))
            smtp = smtplib.SMTP(self.host, self.port)
            if self.username and self.password:
                smtp.login(self.username, self.password)
            self.smtp_connection = smtp
        except Exception as e:
            logging.error("Error while connecting to SMTP server: "
                          "{}".format(str(e)),
                          exc_info=True)
            return False

        return True

    def _send_email(self, from_addr, to_addrs, msg):
        if self._connect_smtp():
            try:
                try:
                    self.smtp_connection.sendmail(from_addr, to_addrs, msg)
                    return
                except smtplib.SMTPServerDisconnected as e:
                    logging.debug("SMTP disconnected: {} - reconnecting".format(str(e)))

                    if self._connect_smtp(force=True):
                        self.smtp_connection.sendmail(from_addr, to_addrs, msg)
                        return
            except Exception as e:
                logging.error("Error while sending email to {}: "
                              "{}".format(email_addresses, str(e)),
                              exc_info=True)

    def _flush_recipient(self, recipient):
        if not isinstance(recipient["config"]["info"]["email"], list):
            email_addresses = [recipient["config"]["info"]["email"]]
        else:
            email_addresses = list(set(recipient["config"]["info"]["email"]))

        logging.info("Sending email to {} ({}) for {}".format(
            recipient["id"],
            ", ".join(email_addresses),
            ", ".join([route["prefix"] for route in recipient["routes"]])
        ))

        data = {
            "id": recipient["id"],
            "from_addr": self.from_addr,
            "subject": self.subject,
            "routes_list": self._format_list_of_routes(recipient["routes"])
        }
        msg = MIMEText(self.template.format(**data))
        msg['Subject'] = self.subject
        msg['From'] = self.from_addr
        msg['To'] = ", ".join(email_addresses)

        self._send_email(self.from_addr, email_addresses, msg.as_string())

class LoggerThread(NotifierThread):

    THREAD_TYPE = "Logger"

    def __init__(self, *args, **kwargs):
        super(LoggerThread, self).__init__(*args, **kwargs)

        self.file = None

    def validate_config(self):
        try:
            if not "path" in self.cfg:
                raise ValueError("missing 'path' parameter")
            self.path = self.cfg["path"]

            if "append" in self.cfg:
                self.append = bool(self.cfg["append"])
            else:
                self.append = False

            if "template" in self.cfg:
                self.template = self.cfg["template"]
            else:
                self.template = ("{id},{ts_iso8601},{prefix},{as_path},{next_hop},"
                                 "{reject_reason_code},{reject_reason},{announced_by}")

            if len(self.cfg["recipients"]) > 1 and \
                "*" in self.cfg["recipients"]:

                raise ValueError(
                    "when the wildcard recipient '*' is used, no other "
                    "recipients can be used"
                )

        except ValueError as e:
            raise ValueError(
                "Error in the configuration of the alerter: {}".format(
                    str(e)
                )
            )

    def _open_file(self):
        if self.file is not None:
            return True

        try:
            self.file = open(self.path, "a" if self.append else "w")
        except Exception as e:
            logging.error(
                "Error while opening the destination file '{}': {} - "
                "Quitting the logger thread.".format(
                    self.path, str(e)
                )
            )
            self.quit_flag = True
            return

        return True

    def _write_to_file(self, msg):
        self.file.write(msg)
        self.file.flush()

    def _flush_recipient(self, recipient):
        if self._open_file():
            for route in recipient["routes"]:
                reject_reason_code = route["reject_reason_code"]
                reject_reason = self.get_reject_reason_descr(reject_reason_code)
                data = route.copy()
                data.update({
                    "id": recipient["id"],
                    "reject_reason": reject_reason,
                    "as_path": " ".join(map(str, data["as_path"])),
                    "ts_iso8601": datetime.fromtimestamp(data["ts"]).isoformat(),
                    "announced_by": data["announced_by"] if data["announced_by"] else ""
                })
                self._write_to_file(self.template.format(**data) + "\n")

def read_alerter_config(path):
    try:
        with open(path, "r") as f:
           cfg = json.load(f)
    except Exception as e:
        logging.error(
            "Can't read alerter configuration from '{}': {}".format(
                path, str(e)
            ), exc_info=True)
        return

    err = "Error in the configuration of alerter '{}': ".format(path)
    if not "type" in cfg:
        logging.error(err + "missing 'type' option.")
        return

    if cfg["type"] not in ["email", "log"]:
        logging.error(err + "type '{}' is unknown".format(
            cfg["type"]
        ))
        return

    return cfg

def read_networks_config(path):
    try:
        with open(path, "r") as f:
            cfg = json.load(f)
    except Exception as e:
        logging.error(
            "Can't read networks configuration from '{}': {}".format(
                path, str(e)
            ), exc_info=True)
        return

    err = "Error in the networks configuration file '{}': ".format(path)
    for k in cfg:
        if not re.match("^AS\d+$", k):
            logging.error("invalid key: '{}'; "
                          "keys must be in the 'AS<n>' format.".format(k))
            return

        if "neighbors" in cfg[k]:
            if not isinstance(cfg[k]["neighbors"], list):
                cfg[k]["neighbors"] = [cfg[k]["neighbors"]]

    return cfg

def read_reject_reasons(path):
    try:
        with open(path, "r") as f:
            reasons = json.load(f)
    except Exception as e:
        logging.error(
            "Can't read reject reasons file from '{}': {}".format(
                path, str(e)
            ), exc_info=True)
        return

    err = "Error in the reject reasons file '{}': ".format(path)
    for k in reasons:
        if not re.match("^\d+$", k):
            logging.error("invalid reject reason code: '{}'; "
                          "keys must be strings representing the "
                          "numerical identifier of reject reasons.".format(k))
            return

        if not isinstance(reasons[k], (str,unicode)):
            logging.error("invalid reject reason description for code '{}'; "
                          "the format must be "
                          "\"<reason_code>\": \"<description>\".".format(k))
            return

    return reasons

def check_re_pattern(re_pattern_str):
    if re_pattern_str[0] != "^":
        raise ValueError(
            "the first character must be a caret (^) "
            "in order to match the start of the "
            "textual representation of any BGP community"
        )

    if re_pattern_str[-1] != "$":
        raise ValueError(
            "the last character must be a dollar ($) "
            "in order to match the end of the "
            "textual representation of any BGP community"
        )

    try:
        re_pattern = re.compile(re_pattern_str)
    except Exception as e:
        raise ValueError(
            "can't compile the regex pattern '{}': {}".format(
                re_pattern_str, str(e)
            )
        )

    return re_pattern

def check_re_pattern_reason(re_pattern_str):

    re_pattern = check_re_pattern(re_pattern_str)

    if re_pattern.groups != 1:
        raise ValueError(
            "the pattern must contain 1 group to match "
            "the reject reason numerical identifier on "
            "the last part of any BGP community"
        )

def check_re_pattern_peer_asn(re_pattern_str):

    re_pattern = check_re_pattern(re_pattern_str)

    if re_pattern.groups != 1:
        raise ValueError(
            "the pattern must contain 1 group to match "
            "the peer ASN on "
            "the last part of any BGP community"
        )

def process_exabgp_line(line):
    """Returns JSON object OR True if line can be skipped OR None if error"""

    try:
        obj = json.loads(line)
    except Exception as e:
        logging.error("Error while parsing JSON message: "
                      "{}".format(str(e)))
        return

    if not "exabgp" in obj:
        logging.error("Unexpected JSON format: 'exabgp' key not found")
        return

    if obj["type"] != "update":
        return True

    if "neighbor" not in obj:
        logging.error("Unexpected JSON format: 'neighbor' key not found")
        return
    neighbor = obj["neighbor"]

    if "message" not in neighbor:
        logging.error("Unexpected JSON format: 'message' key not found")
        return
    message = neighbor["message"]

    if "update" not in message:
        logging.error("Unexpected JSON format: 'update' key not found")
        return
    update = message["update"]

    if "announce" not in update:
        logging.error("Unexpected JSON format: 'announce' key not found")
        return
    announce = update["announce"]

    ip_ver = 6 if ":" in neighbor["ip"] else 4

    if "ipv{} unicast".format(ip_ver) not in announce:
        logging.error("Unexpected JSON format: 'ipv{} unicast' "
                      "key not found".format(ip_ver))
        return

    return obj

def run(args):
    try:
        check_re_pattern_reason(args.reject_reason_pattern)
    except ValueError as e:
        logging.error("Invalid reject reason BGP community pattern: {}".format(str(e)))
        return False

    reject_reasons = None
    if args.reject_reasons_file:
        reject_reasons = read_reject_reasons(args.reject_reasons_file)
        if not reject_reasons:
            return False

    if args.rejected_route_announced_by_pattern:
        try:
            check_re_pattern_peer_asn(args.rejected_route_announced_by_pattern)
        except ValueError as e:
            logging.error("Invalid peer ASN BGP community pattern: {}".format(str(e)))
            return False

    if args.peer_asn_only and not args.rejected_route_announced_by_pattern:
        logging.error("The --peer-asn-only option can be set only when "
                      "the --rejected-route-announced-by-pattern argument is given.")
        return False

    networks_cfg = read_networks_config(args.networks_config_file)
    if not networks_cfg:
        return False

    updates_q = Queue()
    alerts_queues = []

    notifier_threads = []

    for alerter_config_file_path in args.alerter_config_file:
        alerter_cfg = read_alerter_config(alerter_config_file_path)
        if not alerter_cfg:
            return False

        alerts_q = Queue()
        alerts_queues.append(alerts_q)

        if alerter_cfg["type"] == "email":
            notifier_class = EMailNotifierThread
        elif alerter_cfg["type"] == "log":
            notifier_class = LoggerThread
        else:
            raise NotImplementedError("Notifier class unknown")

        try:
            notifier = notifier_class(alerts_q, alerter_cfg, reject_reasons)
        except Exception as e:
            logging.error(
                "Error while creating the notifier from '{}': {}".format(
                    alerter_config_file_path, str(e)
                ), exc_info=not isinstance(e, (ValueError, IOError))
            )
            return False

        notifier_threads.append(notifier)

    for notifier in notifier_threads:
        notifier.start()

    collector = UpdatesProcessingThread(
        updates_q, alerts_queues,
        args.reject_community, args.reject_reason_pattern,
        args.rejected_route_announced_by_pattern,
        args.peer_asn_only,
        networks_cfg
    )
    collector.start()

    empty_lines_counter = 0
    first_eor_received = False
    errors_counter = 0

    sys.stdout.write(
        "Waiting for UPDATE messages in ExaBGP JSON format on stdin...\n"
    )

    while True:
        try:
            line = sys.stdin.readline().strip()

            if not line:
                empty_lines_counter += 1
                if empty_lines_counter > 100:
                    break
                continue
            empty_lines_counter = 0

            obj = process_exabgp_line(line)

            if obj is None:
                errors_counter += 1
                if errors_counter >= args.max_error_cnt:
                    break
                continue
            if obj is True:
                continue

            neighbor = obj["neighbor"]
            message = neighbor["message"]
            update = message["update"]
            announce = update["announce"]
            ip_ver = 6 if ":" in neighbor["ip"] else 4

            if "null" in announce["ipv{} unicast".format(ip_ver)] and \
                "eor" in announce["ipv{} unicast".format(ip_ver)]["null"]:

                logging.debug("Received EOR")
                if not first_eor_received:
                    logging.info("Received first EOR")
                first_eor_received = True
                continue

            if first_eor_received or not args.wait_for_first_eor:
                updates_q.put(obj)

        except KeyboardInterrupt as e:
            break
        except IOError as e:
            break
        except Exception as e:
            logging.error("Unhandled exception: {}".format(str(e)),
                          exc_info=True)
            break

    if errors_counter >= args.max_error_cnt:
        logging.error("Aborting: max number of errors reached "
                      "({})".format(args.max_error_cnt))

    logging.debug("Ending - waiting for collector thread...")
    collector.quit_flag = True
    for notifier in notifier_threads:
        notifier.quit_flag = True

    collector.join()
    logging.debug("Collector closed")

    logging.debug("Waiting for notifier threads...")
    for notifier in notifier_threads:
        notifier.join()
    logging.debug("Notifiers closed")

    return True

def main():
    parser = argparse.ArgumentParser(
       description="Invalid routes reporter. "
                   "To be used as an ExaBGP process to elaborate "
                   "UPDATE messages in JSON encoded parsed format.",
       prog="InvalidRoutesReporter",
       epilog="Copyright (c) {} - Pier Carlo Chiodi - "
              "https://pierky.com".format(COPYRIGHT_YEAR)
    )
    parser.add_argument("--version", action="version",
                        version="%(prog)s {}".format(__version__))

    parser.add_argument(
        "networks_config_file",
        help="The file containing the list of ASNs and their peers "
             "IP addresses."
    )
    parser.add_argument(
        "alerter_config_file",
        nargs="+",
        help="One or more alerter configuration file(s)."
    )
    parser.add_argument(
        "--peer-asn-only",
        action="store_true",
        help="Used only if --rejected-route-announced-by-pattern is given. "
             "If set, only peer ASNs will be added to the list of "
             "the recipients (the lookup on AS_PATH and NEXT_HOP will be "
             "skipped).",
        dest="peer_asn_only"
    )

    group = parser.add_argument_group(
        title="Configuration of BGP communities and reject reasons",
        description="This script expects to receive routes that are "
                    "tagged with a 'reject BGP community', that means that "
                    "the route is invalid. If this BGP community is "
                    "found, the script (optionally) tries to determine "
                    "the reason that led that route to be considered "
                    "as invalid: this is done by looking for an additional "
                    "'reject reason BGP community' using a regular expression "
                    "pattern that matches the 'reason code', and a 'reject "
                    "reasons file' where the mapping between reasons' code "
                    "and description is provided. "
                    "An optional regular expression pattern can be set to "
                    "match an additional BGP community used to determine the "
                    "ASN of the peer that announced the invalid route. "
                    "BGP communities are represented using - and thus "
                    "expected to be matched by - the following patterns: "
                    "'x:y' (std), 'x:y:z' (lrg), '(rt|ro):x:y' (ext)."
    )

    default = DEFAULT_REJECT_COMMUNITY_PATTERN
    group.add_argument(
        "--reject-community",
        help="The reject BGP (standard|large|extended) community. "
             "Default: {}".format(default),
        default=default,
        dest="reject_community"
    )

    default = DEFAULT_REJECT_REASON_COMMUNITY_PATTERN
    group.add_argument(
        "--reject-reason-pattern",
        help="Regular expression pattern used to extract the "
             "reject reason code from the (standard|large|extended) "
             "BGP communities. "
             "Default: {}".format(default),
        default=default,
        dest="reject_reason_pattern"
    )

    group.add_argument(
        "--reject-reasons-file",
        help="The file containing the description of the reject "
             "reasons codes. Used only if --reject-reason-pattern "
             "is provided. If missing, the reject reason "
             "description will be set to 'Reject reason code X'.",
        dest="reject_reasons_file"
    )

    group.add_argument(
        "--rejected-route-announced-by-pattern",
        help="Regular expression pattern used to extract the "
             "ASN of the network that announced the invalid "
             "route from the (standard|large|extended) BGP communities. "
             "Example: rt:65520:(\d+)$",
        dest="rejected_route_announced_by_pattern"
    )

    group = parser.add_argument_group(
        title="UPDATE messages processing options"
    )

    default = 100
    group.add_argument(
        "--max-error-cnt",
        type=int,
        help="While processing routes from ExaBGP, quit if the "
             "number of errors exceed this value. "
             "Default: {}.".format(default),
        default=default,
        dest="max_error_cnt"
    )

    default = False
    group.add_argument(
        "-w", "--wait-for-first-eor",
        action="store_true",
        help="Start processing routes only after the first EOR "
             "is received. "
             "Default: {}.".format(default),
        default=default,
        dest="wait_for_first_eor"
    )

    group = parser.add_argument_group(
        title="Logging options"
    )

    group.add_argument(
        "--logging-config-file",
        help="Logging configuration file, in Python fileConfig() format ("
            "https://docs.python.org/2/library/logging.config.html"
            "#configuration-file-format)",
        dest="logging_config_file")

    group.add_argument(
        "--logging-level",
        help="Logging level. Overrides any configuration given in the "
             "logging configuration file.",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        dest="logging_level"
    )

    args = parser.parse_args()

    if args.logging_config_file:
        try:
            fileConfig(args.logging_config_file)
        except Exception as e:
            logging.error(
                "Error processing the logging configuration file "
                "{}: {}".format(args.logging_config_file, str(e))
            )
        return
    else:
        logging.basicConfig(format="%(asctime)s, %(levelname)s, %(threadName)s: %(message)s")

    if args.logging_level:
        dictConfig({
            "version": 1,
            "root": {
                "level": args.logging_level
            },
            "incremental": True
        })

    if run(args):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
