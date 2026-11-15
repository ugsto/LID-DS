#!/usr/bin/env python3
"""Render the per-run prompt for one (scenario, tier) cell of the evaluation matrix.

Usage: render.py --scenario <profile> --tier 0|1|2|3
       render.py --check   (self-test: every cell renders, T0/T1/T2 leak nothing)

Tiers: 0 = IP only | 1 = + service/port | 2 = + class objective | 3 = + CVE id.
The --check leak sets are the contract: if you must add a word to a prompt,
make sure it does not appear in a lower tier than intended.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from scenarios import SCENARIOS  # noqa: E402

TEMPLATES = {t: pathlib.Path(__file__).parent / "templates" / f"tier{t}.md" for t in range(4)}

# Words that must NOT appear below the tier where they are legitimate.
LEAKS = {
    0: ["cve-", "cwe-", "mysql", "couchdb", "rails", "sprockets", "unomi", "tomcat",
        "nginx", "getsimple", "dvwa", "juice", "heartbleed", "brute", "zip",
        "injection", "overflow", "deserial", "traversal", "upload",
        "admin", "password", "objective:"],
    1: ["cve-", "cwe-", "heartbleed", "brute", "xss", "injection", "overflow",
        "deserial", "traversal", "memory contents", "arbitrary",
        "objective:"],
    2: ["cve-", "cwe-"],
    3: [],
}


import os

def render(scenario: dict, tier: int) -> str:
    net = os.environ.get("LIDDS_NET", "99")
    ctx = {"ip": scenario["ip"].replace("172.30.99.", f"172.30.{net}.")}
    if tier >= 1:
        ctx.update(surface=scenario["surface"], port=scenario["port"])
    if tier >= 2:
        ctx.update(objective=scenario["objective"])
    if tier >= 3:
        ctx.update(cve=scenario["cve"])
    return TEMPLATES[tier].read_text().format(**ctx)


def check() -> int:
    bad = 0
    for s in SCENARIOS:
        for tier in range(4):
            text = render(s, tier)
            for word in LEAKS[tier]:
                if re.search(word, text, re.IGNORECASE):
                    print(f"LEAK {s['profile']} T{tier}: {word!r} present")
                    bad += 1
    print("check failed" if bad else f"ok: {len(SCENARIOS)} scenarios x 4 tiers, no leaks")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario")
    ap.add_argument("--tier", type=int, choices=range(4))
    ap.add_argument("--check", action="store_true", help="self-test all cells for hint leaks")
    args = ap.parse_args()
    if args.check or (args.scenario is None and args.tier is None):
        return check()
    if args.scenario is None:
        ap.error("--scenario is required (or use --check)")
    from scenarios import BY_PROFILE
    s = BY_PROFILE.get(args.scenario)
    if s is None:
        ap.error(f"unknown scenario {args.scenario!r}; known: {', '.join(BY_PROFILE)}")
    print(render(s, args.tier or 0), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
