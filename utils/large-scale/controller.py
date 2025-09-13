#!/usr/bin/env python3

import json
import logging
import os
import pathlib
import sys
import time

import defs
from peering import AnnouncementController, Update


BASEDIR = "phase1_anycast_withdraw1"
UPDATES = defs.phase1_anycast_withdraw1()


def main():
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s"
    )
    handler = logging.getLogger()
    handler.addHandler(logging.FileHandler("controller.log"))

    logging.info("Starting experiment %s", BASEDIR)
    logging.info("Will deploy %d announcements", len(UPDATES))

    controller = AnnouncementController(
        defs.BIRD_CFG_DIR, defs.BIRD4_SOCK_PATH, defs.ANNOUNCEMENT_SCHEMA
    )

    tstamps = {}
    done = False
    roundidx = 0
    while not done:
        roundidx += 1
        tstamps["round-start"] = time.time()
        defs.withdraw_prefixes(controller)
        pfx2upd: dict[str, Update] = {}
        for prefix in defs.PREFIXES:
            try:
                update = next(UPDATES)
                pfx2upd[prefix] = update
            except StopIteration:
                done = True
                break
        tstamps["deploy-pfx2ann"] = time.time()
        defs.deploy_pfx2ann(controller, pfx2upd)

        round_outdir = pathlib.Path(f"{BASEDIR}/round{roundidx}")
        os.makedirs(round_outdir, exist_ok=True)
        with open(round_outdir / "announcements.json", "w", encoding="utf8") as fd:
            json.dump(pfx2upd, fd, indent=2, default=lambda x: x.to_dict())

        tstamps["measure-catchments-start"] = time.time()
        defs.measure_catchments(round_outdir, tstamps)
        tstamps["measure-catchments-end"] = time.time()
        catch_runtime = tstamps["CatchmentMeasurementEnd"] - tstamps["CatchmentMeasurementStart"]
        logging.info("Took %f seconds to measure catchments", catch_runtime)

        round_wait = defs.ANNOUNCEMENT_DURATION - tstamps["AnnouncementDeployment"]
        logging.info("Sleeping additional %f seconds to complete round duration", round_wait)
        time.sleep(round_wait)



if __name__ == "__main__":
    sys.exit(main())
