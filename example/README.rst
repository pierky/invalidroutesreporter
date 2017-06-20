Configuration example for ``invalidroutesreporter``
===================================================

- ``exabgp.conf`` is used to configure a BGP session with the route server and to execute a process running this script. The arguments to run the script are:

  - the file where networks are configured (``/etc/exabgp/networks.json``)

  - one or more files where alerters are configured (``/etc/exabgp/log.alerter.json`` and ``/etc/exabgp/email.alerter.json``).

- ``networks.json`` contains the list of networks that are taken into account for invalid routes monitoring.

- ``log.alerter.json`` is an alerter used to log any invalid route to ``/etc/exabgp/bad_routes.log``.

- ``email.alerter.json`` is another alerter used to send an email message to the networks involved in cases of invalid routes detection; the template file at ``template`` is used to build the body of the email messages.

For more details please refer to the `documentation <https://invalidroutesreporter.readthedocs.io>`_.
