#!/usr/bin/env python3
"""randnet_xp.py - the Randnet bridge for Windows XP.

Windows XP can run Python 3.4 at most (3.4.4 is the last release with an XP
installer). The bridge in ../windows is written to run on 3.4 as well, so
this launcher does not carry a second copy of it. It adds what an XP machine
lacks:

  * pyserial 3.0.1, shipped here as a wheel and used without installing.
    pyserial 3.1 and newer cannot run on XP (they need CancelIoEx, a Vista
    API); a newer copy installed in site-packages is skipped
  * a current CA bundle (network.ca_file), because XP's own root
    certificates are too old to verify today's servers
  * a config with those two set: randnet_xp.conf

  python randnet_xp.py                 runs with randnet_xp.conf
  python randnet_xp.py --probe         asks the modem what it supports
  python randnet_xp.py --self-test     offline checks
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WINDOWS = os.path.join(ROOT, "windows")


def main():
    if sys.version_info < (3, 4):
        sys.exit("randnet_xp needs Python 3.4 or newer; this is %d.%d. "
                 "Python 3.4.4 is the last version for Windows XP."
                 % sys.version_info[:2])
    if not os.path.isfile(os.path.join(WINDOWS, "randnet_win.py")):
        sys.exit("The bridge itself lives in %s, which is missing. Copy the "
                 "whole randnetpi3-main folder to this PC, not only "
                 "windows-xp." % WINDOWS)

    # ..\windows first, so a stray older randnet_win.py in this folder or the
    # main folder cannot shadow the real one.
    for path in (HERE, ROOT, WINDOWS):
        if path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)

    import randnet_win
    loaded = os.path.abspath(randnet_win.__file__)
    wheel = getattr(randnet_win, "BUNDLED_WHEEL", "missing")
    if wheel == "missing":
        sys.exit(
            "%s is an older version of the bridge than this launcher (it has "
            "no pyserial selection for XP). Replace it with the current "
            "windows\\randnet_win.py, and delete any other randnet_win.py "
            "copies in %s or %s." % (loaded, HERE, ROOT))
    if os.path.dirname(loaded) != WINDOWS:
        print("Note: using the bridge from %s, not %s" % (loaded, WINDOWS))

    argv = sys.argv[1:]
    standalone = ("--self-test", "--list-ports", "--help", "-h", "--version")
    has_config = any(arg in ("-c", "--config") or arg.startswith("--config=")
                     for arg in argv)
    if not has_config and not any(arg in standalone for arg in argv):
        argv = ["--config", os.path.join(HERE, "randnet_xp.conf")] + argv

    if wheel and "--self-test" not in argv:
        print("Using pyserial from %s" % wheel)
    return randnet_win.main(argv)


if __name__ == "__main__":
    sys.exit(main())
