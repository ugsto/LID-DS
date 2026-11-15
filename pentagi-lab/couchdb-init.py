"""Waits for CouchDB, then runs the LID-DS scenario init (admin/admin + seed data)."""
import logging
import sys
import time
import urllib.error
import urllib.request

HOST = "couchdb:5984"


def couchdb_up() -> bool:
    try:
        urllib.request.urlopen(f"http://{HOST}/", timeout=2)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


for _ in range(90):
    if couchdb_up():
        break
    time.sleep(2)
else:
    sys.exit(f"couchdb at {HOST} never came up")

import init  # noqa: E402  (LID-DS scenarios/CVE-2017-12635_6/victim/init.py, mounted at /srv)

logging.basicConfig(level=logging.INFO)
init(HOST, logging.getLogger(), True)
print("couchdb init done")
