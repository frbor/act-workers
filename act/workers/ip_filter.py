#!/usr/bin/env python3

"""ip filter plugin


Copyright 2020 mnemonic AS <opensource@mnemonic.no>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

echo the first line and return exit status based on IP type:

0 - Not IP address or public IP address
1 - No data
2 - Multicast (RFC 3171, RFC 2373)
3 - Private (RC 1918, RFC 4193)
4 - Unspecified (RFC 5735, RFC 2373)
5 - Reserved (IETF)
6 - Loopback (RF C3330, RFC 2372)
7 - Link local (RF3927)

"""


import ipaddress
import sys
import traceback
from logging import error


def process() -> None:
    """Read ip addresses from stdin"""

    lines = [line.strip() for line in sys.stdin]

    if len(lines) > 1:
        sys.stderr.write(f"Warning: Got {len(lines)} lines, only first line will be used\n")

    if not lines[0]:
        # Empty data
        sys.exit(1)

    print(lines[0])

    try:
        ip = ipaddress.ip_address(lines[0])
    except ValueError:
        # No IP address
        sys.exit(0)

    if ip.is_multicast:
        #  reserved for multicast use. See RFC 3171 (for IPv4) or RFC 2373 (for IPv6).
        sys.exit(2)

    elif ip.is_private:
        # private networks. See RFC 1918 (for IPv4) or RFC 4193 (for IPv6).
        sys.exit(3)

    elif ip.is_unspecified:
        # unspecified. See RFC 5735 (for IPv4) or RFC 2373 (for IPv6).
        sys.exit(4)

    elif ip.is_reserved:
        # IETF reserved.
        sys.exit(5)

    elif ip.is_loopback:
        # loopback address. See RFC 3330 (for IPv4) or RFC 2373 (for IPv6).
        sys.exit(6)

    elif ip.is_link_local:
        # link-local usage. See RFC 3927.
        sys.exit(7)

    else:
        # Other IP address
        sys.exit(0)


def main() -> None:
    """Main function"""

    process()


def main_log_error() -> None:
    "Main function wrapper. Log all exceptions to error"
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise


if __name__ == '__main__':
    main_log_error()
