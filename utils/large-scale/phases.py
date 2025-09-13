from peering import Announcement, MuxName, PeeringCommunities, Update
from peering import IXP_SPECIAL_PEERS_V4

AS_PATH_PREPEND_LIST = [47065, 47065, 47065]


def phase1a() -> list[Update]:
    updates = []
    for mux in MuxName:
        description = f"anycast+withdraw:{mux}"
        withdraw = [mux]
        muxes = set(MuxName)
        muxes.discard(mux)
        announce = [Announcement(list(muxes))]
        updates.append(Update(withdraw, announce, description))
    return updates


def phase1b() -> list[Update]:
    updates = []
    for mux, asn2peerids in IXP_SPECIAL_PEERS_V4.items():
        for peerids in asn2peerids.values():
            description = f"anycast+withdraw:{mux}+announce:{','.join(p for p in peerids)}"
            withdraw = []
            muxes = set(MuxName)
            muxes.discard(mux)
            communities = [PeeringCommunities.announce_to(pid) for pid in peerids]
            announce1 = Announcement([mux], communities=communities)
            announce2 = Announcement(list(muxes))
            announce = [announce1, announce2]
            updates.append(Update(withdraw, announce, description))
    return updates


def phase2a() -> list[Update]:
    updates = []
    for mux in MuxName:
        description = f"anycast+prepend:{mux}"
        withdraw = []
        muxes = set(MuxName)
        muxes.discard(mux)
        announce1 = Announcement([mux], prepend=AS_PATH_PREPEND_LIST)
        announce2 = Announcement(list(muxes))
        announce = [announce1, announce2]
        updates.append(Update(withdraw, announce, description))
    return updates


def phase2b() -> list[Update]:
    updates = []
    for mux, asn2peerids in IXP_SPECIAL_PEERS_V4.items():
        for peerids in asn2peerids.values():
            description = f"anycast+withdraw:{mux}+prepend:{','.join(p for p in peerids)}"
            withdraw = []
            muxes = set(MuxName)
            muxes.discard(mux)
            communities = [PeeringCommunities.announce_to(pid) for pid in peerids]
            announce1 = Announcement([mux], prepend=AS_PATH_PREPEND_LIST, communities=communities)
            announce2 = Announcement(list(muxes))
            announce = [announce1, announce2]
            updates.append(Update(withdraw, announce, description))
    return updates


