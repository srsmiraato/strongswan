#!/usr/bin/env python

import vici
import logging
from logging.handlers import SysLogHandler
import sys
import os
import subprocess
import signal

# simple daemonization (on production systems python-daemon might be better)
def daemonize():
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = file("/dev/null", 'r')
    so = file("/dev/null", 'a+')
    se = file("/dev/null", 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

logger = logging.getLogger('updownLogger')
handler = SysLogHandler(address='/dev/log', facility=SysLogHandler.LOG_DAEMON)
handler.setFormatter(logging.Formatter('updown: %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

logger.debug("starting Python updown listener")

daemonize()

try:
    v = vici.Session()

    ver = v.version()
    logger.info("connected to {daemon} {version} ({sysname}, {release}, {machine})".format(**ver))
except:
    logger.error("failed to get status via vici")
    sys.exit(1)

try :
    for label, event in v.listen(["ike-updown", "child-updown"]):
        logger.debug("received event: %s %s", label, repr(event))

        if label == "ike-updown":
            name = next((key for key in iter(event) if key != "up"))
            if_id_in = int(event[name]['if-id-in'], 16)
            if_id_out = int(event[name]['if-id-out'], 16)
            ifname_in = "xfrm-{}-in".format(if_id_in)
            ifname_out = "xfrm-{}-out".format(if_id_out)

            if event.get("up", "") == "yes":
                logger.info("add XFRM interfaces %s and %s", ifname_in, ifname_out)
                subprocess.call(["/usr/local/libexec/ipsec/xfrmi", "-n", ifname_out,
                                 "-i", str(if_id_out), "-d", "eth0"])
                subprocess.call(["/usr/local/libexec/ipsec/xfrmi", "-n", ifname_in,
                                 "-i", str(if_id_in), "-d", "eth0"])
                subprocess.call(["ip", "link", "set", ifname_out, "up"])
                subprocess.call(["ip", "link", "set", ifname_in, "up"])
                subprocess.call(["iptables", "-A", "FORWARD", "-o", ifname_out, "-j", "ACCEPT"])
                subprocess.call(["iptables", "-A", "FORWARD", "-i", ifname_in, "-j", "ACCEPT"])

            else:
                logger.info("delete XFRM interfaces %s and %s", ifname_in, ifname_out)
                subprocess.call(["iptables", "-D", "FORWARD", "-o", ifname_out, "-j", "ACCEPT"])
                subprocess.call(["iptables", "-D", "FORWARD", "-i", ifname_in, "-j", "ACCEPT"])
                subprocess.call(["ip", "link", "del", ifname_out])
                subprocess.call(["ip", "link", "del", ifname_in])

        elif label == "child-updown" and event.get("up", "") == "yes":
            name = next((key for key in iter(event) if key != "up"))
            if_id_out = int(event[name]['if-id-out'], 16)
            ifname_out = "xfrm-{}-out".format(if_id_out)
            child = next(event[name]["child-sas"].itervalues())

            for ts in child['remote-ts']:
                logger.info("add route to %s via %s", ts, ifname_out)
                subprocess.call(["ip", "route", "add", ts, "dev", ifname_out])
except IOError as e:
    logger.error("daemon disconnected")
except:
    logger.error("unable to register for events " + repr(sys.exc_info()[0]))
