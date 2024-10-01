#!/usr/bin/env python3.11

from __future__ import annotations

import bz2
import enum
import json
import logging
import os
import re
import sys
import time
from collections import Counter, defaultdict, deque
from ipaddress import IPv4Network
from pathlib import Path
from typing import IO, Callable

import asrel
import ixpfxdb
from peering import Announcement, AnnouncementController, Update, UpdateSet


DATADIR = Path("data")
OUTDIR = Path("output")

MIN_COMMUNITIES = 3
MAX_COMMUNITIES = 10
ROUND_DURATION_SECS = 90 * 60
WITHDRAWAL_DURATION_SECS = 10 * 60

PREFIXES = [
    "184.164.231.0/24",
    "184.164.234.0/24",
    "184.164.235.0/24",
    "184.164.250.0/24",
    "184.164.251.0/24",
]
IGNORED_INDIRECT_UPSTREAMS = [
    13335,  # Cloudflare
    8075,  # Microsoft
    15169,  # Google
    16509,  # AWS
    32934,  # Facebook
    36351,  # Softlayer/IBM
]


class PeeringMux(enum.StrEnum):
    AMSTERDAM = "amsterdam01"
    CLEMSON = "clemson01"
    GATECH = "gatech01"
    GRNET = "grnet01"
    ISI = "isi01"
    NEU = "neu01"
    PHOENIX = "phoenix01"
    SAOPAULO = "saopaulo01"
    SBU = "sbu01"
    SEATTLE = "seattle01"
    UFMG = "ufmg01"
    UFMS = "ufms01"
    UTAH = "utah01"
    UW = "uw01"
    WISC = "wisc01"


class VultrMux(enum.StrEnum):
    MIAMI = "miami"
    ATLANTA = "atlanta"
    AMSTERDAM = "amsterdam"
    TOKYO = "tokyo"
    SYDNEY = "sydney"
    FRANKFURT = "frankfurt"
    SEATTLE = "seattle"
    CHICAGO = "chicago"
    PARIS = "paris"
    SINGAPORE = "singapore"
    WARSAW = "warsaw"
    NEWYORK = "newyork"
    DALLAS = "dallas"
    MEXICO = "mexico"
    TORONTO = "toronto"
    MADRID = "madrid"
    STOCKHOLM = "stockholm"
    BANGALORE = "bangalore"
    DELHI = "delhi"
    LOSANGELAS = "losangelas"
    SILICON = "silicon"
    LONDON = "london"
    MUMBAI = "mumbai"
    SEOUL = "seoul"
    MELBOURNE = "melbourne"
    SAOPAULO = "saopaulo"
    JOHANNESBURG = "johannesburg"
    OSAKA = "osaka"


class Relationship(enum.StrEnum):
    Provider = "provider"
    PublicPeer = "public-peer"
    PrivatePeer = "private-peer"
    RouteServer = "route-server"
    Customer = "customer"
    Owned = "owned"

    @staticmethod
    def from_vultr_tag(tag: int) -> Relationship:
        match tag:
            case 100:
                return Relationship.Provider
            case 200:
                return Relationship.PublicPeer
            case 300:
                return Relationship.PrivatePeer
            case 400:
                return Relationship.Customer
            case 4000:
                return Relationship.Customer
            case 500:
                return Relationship.Owned
        raise RuntimeError(f"Unknown Vultr tag: {tag}")


PEERING_ORIGIN = 47065
IGNORED_ASNS = set([])


PeerMap = dict[int, dict[PeeringMux | VultrMux, int]]
BGPComm = tuple[int, int]


def load_peering_peers() -> dict[Relationship, PeerMap]:
    rel2asn2mux2pid: dict[Relationship, PeerMap] = defaultdict(
        lambda: defaultdict(dict)
    )
    with open(DATADIR / "peers.json", encoding="utf8") as fd:
        peers = json.load(fd)
    for peer in peers:
        if peer["IP version"] != "IPv4":
            continue
        rel = Relationship.PrivatePeer
        if peer["Transit"]:
            rel = Relationship.Provider
        elif peer["Route Server"]:
            rel = Relationship.RouteServer
        if peer["BGP Mux"] in ["cornell01", "fabric-wash"]:
            continue
        mux = PeeringMux(peer["BGP Mux"])
        asn = int(peer["Peer ASN"])
        pid = int(peer["Session ID"])
        rel2asn2mux2pid[rel][asn][mux] = pid
    logging.info("Loaded %d peers across all PEERING muxes", len(peers))
    return rel2asn2mux2pid


def load_vultr_peers() -> dict[Relationship, PeerMap]:
    regex = re.compile(r"peers_(?P<mux>.*)_new.txt")
    rel2asn2muxes: dict[Relationship, PeerMap] = defaultdict(lambda: defaultdict(dict))
    vdir = DATADIR / "vultr-peers"
    peers = 0
    for fp in vdir.glob("peers*.txt"):
        m = regex.match(str(fp.name))
        assert m is not None
        mux = VultrMux(m.group("mux"))
        with open(fp, encoding="utf8") as fd:
            for line in fd:
                asnstr, tagstr = line.strip().split("\t")
                if tagstr == "NA":
                    continue
                asn, tag = int(asnstr), int(tagstr)
                rel = Relationship.from_vultr_tag(tag)
                rel2asn2muxes[rel][asn][mux] = asn
                peers += 1
    logging.info("Loaded %d peers across all Vultr muxes", peers)
    return rel2asn2muxes


def load_asn2ccsize() -> dict[int, int]:
    asn2ccsize = {}
    with bz2.open(DATADIR / "20230301.ppdc-ases.txt.bz2", "rt") as fd:
        for line in fd:
            if line.startswith("#"):
                continue
            fields = line.split()
            asn = int(fields[0])
            ccsize = len(fields) - 1
            asn2ccsize[asn] = ccsize
    logging.info("Loaded customer cone sizes of %d ASNs", len(asn2ccsize))
    return asn2ccsize


def load_asn2pending() -> dict[int, list[int]]:
    asn2pending = defaultdict(list)
    with open(DATADIR / "test-action-comms.txt", encoding="utf8") as fd:
        for line in fd:
            line = line.strip()
            asn, comm = line.split(":")
            asn2pending[int(asn)].append(int(comm))
    logging.info("Loaded communities from %d ASNs not in GT", len(asn2pending))
    return asn2pending


def load_ixp_asns():
    pfxdb = ixpfxdb.IXPrefixDB(DATADIR / "ixp-prefixes.json")
    ixpasns = set()
    for pfxdata in pfxdb.pfx2data.values():
        ixpasns.update(pfxdata.org_asns)
    return ixpasns


def get_indirect_providers(direct_providers: PeerMap) -> PeerMap:
    # proceed in breadth-first order to ensure we pick shortest paths to indirect peers
    reldb = asrel.ASRelationshipsDB(DATADIR / "20230301.as-rel.txt.bz2")
    indirect_providers = defaultdict(dict, direct_providers)
    pending: deque[int] = deque(direct_providers.keys())
    iprov2dprov: dict[int, int] = {d: d for d in pending}
    logging.debug("initial direct providers: %s", ",".join(str(t) for t in pending))
    while pending:
        iprov = pending.popleft()
        dprov = iprov2dprov[iprov]
        mux, pid = min(direct_providers[dprov].items())
        logging.debug("proc iprov=%d, dprov=%d, mux=%s, pid=%d", iprov, dprov, mux, pid)
        indirect_providers[iprov][mux] = pid
        newprovs, skipprovs = set(), set()
        for asn in reldb.asn2rel2asns[iprov][asrel.Relationship.C2P]:
            if asn in iprov2dprov or asn in IGNORED_INDIRECT_UPSTREAMS:
                skipprovs.add(asn)
            else:
                newprovs.add(asn)
        logging.debug(
            "skipping %d known indirect providers, newprovs %s",
            len(skipprovs),
            ",".join(str(asn) for asn in newprovs),
        )
        for asn in newprovs:
            iprov2dprov[asn] = dprov
            pending.append(asn)
    logging.info(
        "Can reach %d indirect providers from %d direct",
        len(indirect_providers),
        len(direct_providers),
    )
    return indirect_providers


def choose_communities(
    asn2pending: dict[int, list[int]], asn2ccsize: dict[int, int], asn2mux2pid: PeerMap
) -> dict[int, list[int]]:
    stats: Counter[str] = Counter()
    ixpasns = load_ixp_asns()
    asn2chosen: dict[int, list[int]] = defaultdict(list)
    considered_asns = []
    for asn, pending in asn2pending.items():
        if asn not in asn2mux2pid:
            stats["asn-not-indirect-provider"] += 1
            continue
        if asn in ixpasns:
            stats["asn-is-ixp"] += 1
            continue
        if len(pending) < MIN_COMMUNITIES:
            stats["asn-w-insufficient-communities"] += 1
            continue
        ccsize = asn2ccsize.get(asn, 0)
        considered_asns.append((ccsize, asn))

    considered_asns.sort(reverse=True)
    for _ccsize, asn in considered_asns:
        pending = asn2pending[asn]
        pending.sort()
        if len(pending) < MAX_COMMUNITIES:
            chosen = pending
        else:
            chosen = []
            hstep = len(pending) / MAX_COMMUNITIES
            for i in range(MAX_COMMUNITIES):
                chosen.append(pending[int(i * hstep)])
            assert len(chosen) == 10, (hstep, len(pending), len(chosen))
        asn2chosen[asn] = chosen
    logging.info("Chose communities from %d target ASNs", len(asn2chosen))
    logging.debug("\n".join("=".join(str(i) for i in kv) for kv in stats.items()))
    return asn2chosen


def log_update_set(us: UpdateSet, fd: IO[str]) -> None:
    usdict = us.to_dict()
    usdict["timestamp"] = time.time()
    json.dump(usdict, fd)
    fd.write("\n")
    fd.flush()


def make_withdraw_update_set() -> UpdateSet:
    muxes = list(str(m) for m in PeeringMux) + list(str(m) for m in VultrMux)
    return UpdateSet({str(pfx): Update(muxes, []) for pfx in PREFIXES})


def make_peering_update(mux: str, pid: int, asn: int, comm: int | None) -> Update:
    comms: list[BGPComm] = [(47065, pid)]
    if comm is not None:
        comms.append((asn, comm))
    ann = Announcement([mux], [], comms, [], PEERING_ORIGIN)
    return Update([], [ann])


def make_vultr_update(mux: str, pid: int, asn: int, comm: int | None) -> Update:
    # https://github.com/vultr/vultr-docs/tree/main/faq/as20473-bgp-customer-guide#action-communities
    comms: list[BGPComm] = [(20473, 6000), (64699, pid)]
    if comm is not None:
        comms.append((asn, comm))
    ann = Announcement([mux], [], comms, [], PEERING_ORIGIN)
    return Update([], [ann])


def make_update_set(
    commlist: deque[BGPComm],
    asn2mux2pid: PeerMap,
    make_update: Callable[[str, int, int, int | None], Update],
) -> UpdateSet:
    def get_next_comm() -> BGPComm:
        while True:
            asn, comm = commlist.popleft()
            if asn in IGNORED_ASNS:
                logging.info("Skipping %d:%d because ASN is ignored", asn, comm)
                continue
            return asn, comm

    prefix2update: dict[str, Update] = {}
    casn = -1
    i = 0
    while i < len(PREFIXES) - 1:
        try:
            asn, comm = get_next_comm()
        except StopIteration:
            break
        if casn != -1 and casn != asn:
            # allocate sentinel prefix
            mux, pid = min(asn2mux2pid[casn].items())  # choose min for consistency
            prefix2update[PREFIXES[i]] = make_update(mux, pid, casn, None)
            i += 1
        if i == len(PREFIXES) - 1:
            # new ASN, but only one slot left.  punt this community to the next round.
            commlist.appendleft((asn, comm))
            break
        casn = asn
        mux, pid = min(asn2mux2pid[casn].items())  # choose min for consistency
        prefix2update[PREFIXES[i]] = make_update(mux, pid, casn, comm)
        i += 1
    # allocate sentinel prefix
    mux, pid = min(asn2mux2pid[casn].items())
    prefix2update[PREFIXES[i]] = make_update(mux, pid, casn, None)
    return UpdateSet(prefix2update)


def run_peering_announcements(
    asn2pending: dict[int, list[int]],
    asn2ccsize: dict[int, int],
) -> None:
    rel2asn2mux2pid = load_peering_peers()
    indirect_providers = get_indirect_providers(rel2asn2mux2pid[Relationship.Provider])
    asn2chosen = choose_communities(asn2pending, asn2ccsize, indirect_providers)

    asn_comm_pairs = list(
        (asn, comm) for asn, chosen in asn2chosen.items() for comm in chosen
    )
    logging.info("Got %d communities total", len(asn_comm_pairs))

    asn_comm_processed = load_processed_communities(
        OUTDIR / "peering-log-cumulative.jsonl"
    )
    asn_comm_pending = list(ac for ac in asn_comm_pairs if ac not in asn_comm_processed)
    logging.info(
        "Will skip %d communities already processed",
        len(asn_comm_pairs) - len(asn_comm_pending),
    )

    os.makedirs(OUTDIR, exist_ok=True)
    controller = AnnouncementController()

    outfp = OUTDIR / "peering-log.jsonl"
    assert not outfp.exists(), f"File {outfp} exists, please move it before proceeding"
    logfd = open(outfp, "wt", encoding="utf8")

    commq = deque(asn_comm_pending)
    us = make_update_set(commq, indirect_providers, make_peering_update)
    while us.prefix2update:
        logging.info("%f deploying %s", time.time(), us.to_json())
        log_update_set(us, logfd)
        controller.deploy(us)
        logging.info("%f waiting 90 minutes to round end", time.time())
        time.sleep(ROUND_DURATION_SECS)

        us = make_withdraw_update_set()
        logging.info("%f deploying %s", time.time(), us.to_json())
        log_update_set(us, logfd)
        controller.deploy(us)
        logging.info("%f waiting 10 minutes for withdrawal", time.time())
        time.sleep(WITHDRAWAL_DURATION_SECS)

        us = make_update_set(commq, indirect_providers, make_peering_update)

    logfd.close()


def run_vultr_announcements(
    asn2pending: dict[int, list[int]],
    asn2ccsize: dict[int, int],
) -> None:
    rel2asn2muxes = load_vultr_peers()
    indirect_providers = get_indirect_providers(rel2asn2muxes[Relationship.Provider])
    asn2chosen = choose_communities(asn2pending, asn2ccsize, indirect_providers)

    asn_comm_pairs = list(
        (asn, comm) for asn, chosen in asn2chosen.items() for comm in chosen
    )
    logging.info("Got %d communities total", len(asn_comm_pairs))

    asn_comm_processed = load_processed_communities(
        OUTDIR / "vultr-log-cumulative.jsonl"
    )
    asn_comm_pending = list(ac for ac in asn_comm_pairs if ac not in asn_comm_processed)
    logging.info(
        "Will skip %d communities already processed",
        len(asn_comm_pairs) - len(asn_comm_pending),
    )

    os.makedirs(OUTDIR, exist_ok=True)
    controller = AnnouncementController()

    outfp = OUTDIR / "vultr-log.jsonl"
    assert not outfp.exists(), f"File {outfp} exists, please move it before proceeding"
    logfd = open(outfp, "wt", encoding="utf8")

    commq = deque(asn_comm_pending)
    us = make_update_set(commq, indirect_providers, make_vultr_update)
    while us.prefix2update:
        logging.info("%f deploying %s", time.time(), us.to_json())
        log_update_set(us, logfd)
        controller.deploy(us)
        logging.info("%f waiting 90 minutes to round end", time.time())
        time.sleep(ROUND_DURATION_SECS)

        us = make_withdraw_update_set()
        logging.info("%f deploying %s", time.time(), us.to_json())
        log_update_set(us, logfd)
        controller.deploy(us)
        logging.info("%f waiting 10 minutes for withdrawal", time.time())
        time.sleep(WITHDRAWAL_DURATION_SECS)

        us = make_update_set(commq, indirect_providers, make_vultr_update)

    logfd.close()


def load_processed_communities(fp: Path) -> set[tuple[int, int]]:
    asn_comm_processed: set[tuple[int, int]] = set()
    assert fp.exists(), f"File {fp} does not exist; touch it on first run"
    with open(fp, encoding="utf8") as fd:
        for line in fd:
            us: UpdateSet = UpdateSet.from_json(line)
            for update in us.prefix2update.values():
                for announcement in update.announce:
                    asn_comm_processed.update(announcement.communities)
    logging.info("Loaded %d communities already processed", len(asn_comm_processed))
    return asn_comm_processed


def main():
    logging.basicConfig(format="%(message)s", level=logging.DEBUG)

    asn2pending = load_asn2pending()
    asn2ccsize = load_asn2ccsize()

    # run_peering_announcements(asn2pending, asn2ccsize)
    run_vultr_announcements(asn2pending, asn2ccsize)


if __name__ == "__main__":
    sys.exit(main())
