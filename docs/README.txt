This script is intended to be used as an `ExaBGP <https://github.com/Exa-Networks/exabgp>`_ process to elaborate and report/log invalid routes that have been tagged with meaningful dedicated BGP communities by route servers.

Invalid routes are those routes that, for some reason, didn't pass the route server's validation process (invalid/private ASNs in the AS_PATH, bogon prefixes, invalid NEXT_HOP, IRRDBs data mismatch, ...). Route servers, instead of discarding them, can keep these routes and tag them with a BGP community that describes the reason for which they have been considered as invalid.

A session with an ExaBGP-based route collector can be used to announce these invalid routes to this script, that finally processes them, extracts the reject reason and uses this information to log a record or to send an email alert to the involved networks.

If deployed in conjunction with `ARouteServer`_, the `"tag" reject policy option <https://arouteserver.readthedocs.io/en/latest/CONFIG.html#reject-policy>`_ can be used to easily setup the route server to work together with this script.

.. _ARouteServer: https://github.com/pierky/arouteserver
