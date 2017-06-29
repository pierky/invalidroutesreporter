#!/bin/sh
cd /etc/exabgp
./invalidroutesreporter.py \
	networks.json \
	log.alerter.json \
	email.alerter.json \
	--reject-reasons-file arouteserver_reject_reasons.json \
	--rejected-route-announced-by-pattern '^rt:65520:(\d+)$'
