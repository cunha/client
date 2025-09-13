import logging
import os
import pathlib
import subprocess
import time
from ipaddress import IPv4Address, IPv4Network

from peering import AnnouncementController, Update, UpdateSet, MuxName
import peering
import phases

EGRESS_PREFS: list[MuxName] = [
    MuxName.ufmg01,
    MuxName.uw01,
    MuxName.neu01,
]

PREFIXES: list[str] = [
    "184.164.224.0/24",
    "184.164.225.0/24",
    "184.164.226.0/24",
    "184.164.227.0/24",
    "184.164.232.0/24",
    "184.164.233.0/24",
    "184.164.238.0/24",
    "184.164.239.0/24",
    "184.164.246.0/24",
    "184.164.247.0/24",
    "184.164.248.0/24",
    "184.164.249.0/24",
    "184.164.250.0/24",
    "184.164.251.0/24",
]

PROPAGATION_TIME = 600

BIRD_CFG_DIR = pathlib.Path("../../", peering.DEFAULT_BIRD_CFG_DIR)
BIRD4_SOCK_PATH = pathlib.Path("../../", peering.DEFAULT_BIRD4_SOCK_PATH)
ANNOUNCEMENT_SCHEMA = pathlib.Path("../../", peering.DEFAULT_ANNOUNCEMENT_SCHEMA)

TARGETS_FILE = pathlib.Path("data/targets.txt")

CATCHMENTS_DIR = pathlib.Path("../measure-catchments")
CATCHMENTS_ICMPID_BASE = 44000
CATCHMENTS_PINGER_PPS = 600


def phase1_anycast_withdraw1() -> list[peering.Update]:
    return phases.phase1a() + phases.phase1b()


def phase2_anycast_prepend1() -> list[peering.Update]:
    return phases.phase2a() + phases.phase2b()


def withdraw_prefixes(controller: AnnouncementController):
    for prefix in PREFIXES:
        controller.withdraw(prefix)
    controller.reload_config()
    logging.info("Waiting %d seconds for withdrawals to converge", PROPAGATION_TIME)
    time.sleep(PROPAGATION_TIME)


def deploy_pfx2ann(controller: AnnouncementController, pfx2ann: dict[str, Update]):
    updset = UpdateSet(pfx2ann)
    controller.deploy(updset)
    logging.info("PEERING deploy %s %s", time.time(), updset.to_json())
    logging.info("Waiting %d seconds for announcements to propagate", PROPAGATION_TIME)
    time.sleep(PROPAGATION_TIME)


def measure_catchments(outdir: pathlib.Path, tstamps: dict[str, float]):
    muxes = [str(m) for m in peering.MuxName]
    tcpdumpcmd = CATCHMENTS_DIR / "launch-tcpdump.sh"
    pingercmd = CATCHMENTS_DIR / "launch-pinger.sh"
    killcmd = CATCHMENTS_DIR / "kill-tcpdump.sh"
    for prefix in PREFIXES:
        octet = int(IPv4Network(prefix).network_address.packed[2])
        pfxoutdir = f"{outdir}/catchment_{octet}"
        os.makedirs(pfxoutdir, exist_ok=True)
        srcip = str(list(IPv4Network(prefix).hosts())[-1])

        params = [str(tcpdumpcmd), "-i", srcip, "-o", pfxoutdir] + muxes
        logging.debug(str(params))
        tstamps[f"launch-tcpdump@{octet}"] = time.time()
        proc = subprocess.run(params, check=True, text=True, capture_output=True)
        logging.info("launch-tcpdump.sh succeeded for %s at", srcip)
        logging.debug("%s", proc.stdout)

        icmpid = CATCHMENTS_ICMPID_BASE + octet
        params = [
            str(pingercmd),
            "-i",
            str(srcip),
            "-t",
            str(TARGETS_FILE),
            "-I",
            str(icmpid),
            "-r",
            str(CATCHMENTS_PINGER_PPS),
        ]
        logging.debug(str(params))
        tstamps[f"launch-pinger@{octet}"] = time.time()
        proc = subprocess.run(params, check=True, text=True, capture_output=True)
        logging.info("launch-pinger.sh succeeded for %s %s", srcip)

        params = [str(killcmd), "-f", f"{pfxoutdir}/pids.txt"]
        logging.debug(str(params))
        tstamps[f"kill-tcpdump@{octet}"] = time.time()
        proc = subprocess.run(params, check=True, text=True, capture_output=True)
        logging.info("kill-tcpdump.sh succeeded for %s", srcip)
