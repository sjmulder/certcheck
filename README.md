certcheck
=========
Check HTTPS certificate validity times

**certcheck** [-**V**] *host* ...

Decription
----------
Outputs a list of expiry dates for the HTTPS certificates for each of
the given hosts' addresses.

The output has three columns: expiration date (UTC), host, and IP/port.
Since the date is formated like 2022-08-01 12:00, the list can be
trivially sorted by expiration date with _sort(1)_.

The hosts are contacted on port 443 on every resolved address.
Connections are closed immediately after the TLS handshake completes.

Exists 0 on success, or nonzero for usage and initialization errors.
Failed attempt to resolve or contact a host yield a printed warning but
do not cause a nonzero exit.

Example
-------
Show expiry dates for example.com and the nonexistent bad.example.com:

    $ certcheck example.com bad.example.com
    2023-03-14 23:59:59	   example.com	   [2606:2800:220:1:248:1893:25c8:1946]:443
    2023-03-14 23:59:59	   example.com	   [93.184.216.34]:443
    certcheck: bad.example.com: Name or service not known

Installation
------------
No package is currently available but building is fairly
straightforward and should work on any Unix-like. On Debian or Ubuntu:

    sudo apt install build-essential libssl-dev git
    git clone https://github.com/sjmulder/certcheck.git
    cd certcheck
    make
    sudo make install

Author
------
Sijmen J. Mulder (<ik@sjmulder.nl>)
