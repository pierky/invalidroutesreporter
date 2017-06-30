Change log
++++++++++

v0.2.0
------

- New: ``--rejected-route-announced-by-pattern`` argument, to track a BGP community set with the peer that actually announced the invalid route.

- New: ``--peer-asn-only`` option, to send alerts only to the peers that announced invalid routes.

v0.1.0
------

First release as a standalone repository.

- New: make the *reject reason BGP community* optional and track also routes tagged with a *reject BGP community* only.

- New: optional external file containing the reason-code/description matrix.

- Fix: extended BGP communities processing.

- Improvement: ``min_wait`` and ``max_wait`` timers handling.
