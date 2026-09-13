import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.mesh_simulator import MeshSimulatorService
from app.models import MeshPacket


def test_gossip_propagates_to_all_devices():
    mesh = MeshSimulatorService()
    packet = MeshPacket.wrap(b"fake-ciphertext", ttl=5)
    mesh.inject(packet, origin_device_id="phone-alice")

    assert mesh.devices["phone-alice"].packets

    mesh.gossip_round()
    for device in mesh.devices.values():
        assert packet.packet_id in device.packets


def test_ttl_expires_eventually():
    mesh = MeshSimulatorService()
    packet = MeshPacket.wrap(b"fake-ciphertext", ttl=1)
    mesh.inject(packet, origin_device_id="phone-alice")

    mesh.gossip_round()  # ttl 1 -> 0 on hop, so it should NOT propagate further
    non_origin_holders = [
        d for name, d in mesh.devices.items()
        if name != "phone-alice" and packet.packet_id in d.packets
    ]
    assert non_origin_holders == []


def test_reset_clears_all_devices():
    mesh = MeshSimulatorService()
    packet = MeshPacket.wrap(b"x", ttl=5)
    mesh.inject(packet)
    mesh.gossip_round()
    mesh.reset()
    for device in mesh.devices.values():
        assert len(device.packets) == 0