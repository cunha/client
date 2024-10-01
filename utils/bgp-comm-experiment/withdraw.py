#!/usr/bin/env python3

import logging
import sys
from ipaddress import IPv4Network

from peering import AnnouncementController, Update, UpdateSet

PREFIX_PAIRS = [
    (IPv4Network("184.164.224.0/24"), IPv4Network("184.164.225.0/24")),
    (IPv4Network("184.164.234.0/24"), IPv4Network("184.164.235.0/24")),
    (IPv4Network("184.164.250.0/24"), IPv4Network("184.164.251.0/24")),
    (IPv4Network("184.164.231.0/24"), IPv4Network("184.164.248.0/24")),
]
PEERING_MUXES = [
    "amsterdam01",
    "clemson01",
    "grnet01",
    "isi01",
    "neu01",
    "phoenix01",
    "saopaulo01",
    "sbu01",
    "seattle01",
    "ufmg01",
    "ufms01",
    "utah01",
    "uw01",
    "wisc01",
]
PEERING_ORIGIN = 47065


def make_withdraw_update_set() -> UpdateSet:
    prefix2update = {}
    for spfx, epfx in PREFIX_PAIRS:
        prefix2update[str(spfx)] = Update(PEERING_MUXES, [])
        prefix2update[str(epfx)] = Update(PEERING_MUXES, [])
    return UpdateSet(prefix2update)


def main():
    logging.basicConfig(format="%(message)s", level=logging.DEBUG)
    us = make_withdraw_update_set()
    controller = AnnouncementController()
    controller.deploy(us)


if __name__ == "__main__":
    sys.exit(main())
