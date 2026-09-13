"""
mesh_simulator.py
-------------------
Python port of MeshSimulatorService.java.

Simulates a Bluetooth-style gossip mesh on a single process: every device
that holds a packet broadcasts it to every other device ("Bluetooth range"
== everyone, in this simulator), decrementing TTL per hop. One device is
flagged has_internet=True and plays the role of the "bridge" that walks
outside and uploads to the backend.
"""

import copy
import dataclasses

from .models import MeshPacket, VirtualDevice

DEFAULT_DEVICE_IDS = ["phone-alice", "phone-stranger1", "phone-stranger2", "phone-bridge", "phone-carol"]
BRIDGE_DEVICE_IDS = {"phone-bridge"}


class MeshSimulatorService:
    def __init__(self):
        self.devices: dict[str, VirtualDevice] = {}
        self.reset()

    def reset(self):
        self.devices = {
            device_id: VirtualDevice(device_id=device_id, has_internet=device_id in BRIDGE_DEVICE_IDS)
            for device_id in DEFAULT_DEVICE_IDS
        }

    def inject(self, packet: MeshPacket, origin_device_id: str = "phone-alice"):
        """The sender's own phone is the first device to hold the packet."""
        self.devices[origin_device_id].receive(packet)

    def gossip_round(self) -> int:
        """
        One round: every device broadcasts every packet it holds to every
        OTHER device. TTL decrements per hop. Returns the number of new
        (device, packet) deliveries that happened this round, so the caller
        can tell when the mesh has saturated (0 new deliveries).
        """
        # Snapshot what everyone holds *before* this round, so a packet
        # can't hop twice in the same round through a device that just
        # received it.
        snapshot: dict[str, list[MeshPacket]] = {
            device_id: list(device.packets.values())
            for device_id, device in self.devices.items()
        }

        new_deliveries = 0
        for sender_id, packets in snapshot.items():
            for packet in packets:
                hopped = dataclasses.replace(packet, ttl=packet.ttl - 1)
                if hopped.ttl <= 0:
                    continue
                for receiver_id, receiver_device in self.devices.items():
                    if receiver_id == sender_id:
                        continue
                    if receiver_device.receive(hopped):
                        new_deliveries += 1
        return new_deliveries

    def bridges_flush(self, ingest_fn) -> list[dict]:
        """
        Every device with has_internet=True 'walks outside' and POSTs every
        packet it holds to the backend (ingest_fn), in parallel (mirrors the
        original's parallel upload). Returns a list of result dicts tagged
        with which bridge and packet they came from.
        """
        import concurrent.futures

        jobs = []
        for device_id, device in self.devices.items():
            if not device.has_internet:
                continue
            for packet in list(device.packets.values()):
                jobs.append((device_id, packet))

        results = []
        if not jobs:
            return results

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(jobs))) as pool:
            future_to_job = {pool.submit(ingest_fn, packet): (device_id, packet) for device_id, packet in jobs}
            for future in concurrent.futures.as_completed(future_to_job):
                device_id, packet = future_to_job[future]
                result = future.result()
                results.append({
                    "bridgeDeviceId": device_id,
                    "packetId": packet.packet_id,
                    **result.to_dict(),
                })

        return results

    def state(self) -> dict:
        return {
            device_id: {
                "hasInternet": device.has_internet,
                "packetCount": len(device.packets),
                "packetIds": list(device.packets.keys()),
            }
            for device_id, device in self.devices.items()
        }