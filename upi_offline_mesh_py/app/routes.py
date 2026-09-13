"""
routes.py
----------
HTTP layer. Python port of controller/ApiController.java +
controller/DashboardController.java.

Endpoint map (identical paths/methods to the Java version):

    GET  /                    Dashboard HTML
    GET  /api/server-key      Server's RSA public key (base64)
    GET  /api/accounts        All accounts and balances
    GET  /api/transactions    Last 20 transactions
    GET  /api/mesh/state      Current state of every virtual device
    POST /api/demo/send       Simulate sender phone -> encrypt + inject packet
    POST /api/mesh/gossip     Run one round of gossip across the mesh
    POST /api/mesh/flush      Bridges with internet upload to backend
    POST /api/mesh/reset      Clear mesh + idempotency cache
    POST /api/bridge/ingest   THE production endpoint. Real bridges POST here
"""

from flask import Blueprint, current_app, jsonify, render_template, request

from .models import MeshPacket

bp = Blueprint("routes", __name__)


def services():
    return current_app.services


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------

@bp.route("/")
def dashboard():
    return render_template("dashboard.html")


# --------------------------------------------------------------------------
# Read-only info endpoints
# --------------------------------------------------------------------------

@bp.route("/api/server-key")
def server_key():
    return jsonify({"publicKeyBase64": services().key_holder.public_key_base64()})


@bp.route("/api/accounts")
def accounts():
    svc = services()
    return jsonify([
        {
            "accountId": a.account_id,
            "ownerName": a.owner_name,
            "balanceRupees": a.balance_rupees(),
            "version": a.version,
        }
        for a in svc.accounts.all()
    ])


@bp.route("/api/transactions")
def transactions():
    svc = services()
    return jsonify([
        {
            "id": t.id,
            "senderId": t.sender_id,
            "receiverId": t.receiver_id,
            "amountRupees": t.amount_paise / 100.0,
            "packetHash": t.packet_hash,
            "status": t.status,
            "reason": t.reason,
            "settledAt": t.settled_at,
        }
        for t in svc.transactions.last(20)
    ])


@bp.route("/api/mesh/state")
def mesh_state():
    return jsonify(services().mesh.state())


# --------------------------------------------------------------------------
# Demo-driving endpoints (used by the dashboard buttons)
# --------------------------------------------------------------------------

@bp.route("/api/demo/send", methods=["POST"])
def demo_send():
    """
    Step 1 of the demo: 'Compose a payment' / Inject into Mesh.
    Body: {"senderId": "alice", "receiverId": "bob", "amountRupees": 500, "pin": "1234"}
    """
    svc = services()
    body = request.get_json(force=True) or {}

    sender_id = body.get("senderId", "alice")
    receiver_id = body.get("receiverId", "bob")
    amount_rupees = float(body.get("amountRupees", 500))
    pin = str(body.get("pin", "1234"))
    ttl = int(body.get("ttl", 5))
    origin_device = body.get("originDeviceId", "phone-alice")

    packet = svc.demo.create_packet(sender_id, receiver_id, amount_rupees, pin, ttl=ttl)
    svc.mesh.inject(packet, origin_device_id=origin_device)

    return jsonify({
        "packetId": packet.packet_id,
        "ttl": packet.ttl,
        "injectedAtDevice": origin_device,
        "meshState": svc.mesh.state(),
    })


@bp.route("/api/mesh/gossip", methods=["POST"])
def mesh_gossip():
    """Step 2: 'Run Gossip Round'."""
    svc = services()
    new_deliveries = svc.mesh.gossip_round()
    return jsonify({
        "newDeliveries": new_deliveries,
        "meshState": svc.mesh.state(),
    })


@bp.route("/api/mesh/flush", methods=["POST"])
def mesh_flush():
    """Step 3: 'Bridges Upload to Backend'. Every phone with internet POSTs
    every packet it holds to the ingest pipeline, in parallel."""
    svc = services()
    results = svc.mesh.bridges_flush(svc.bridge_ingestion.ingest)
    return jsonify({
        "results": results,
        "accounts": [
            {"accountId": a.account_id, "balanceRupees": a.balance_rupees()}
            for a in svc.accounts.all()
        ],
    })


@bp.route("/api/mesh/reset", methods=["POST"])
def mesh_reset():
    """Reset mesh state, idempotency cache, and re-seed accounts."""
    svc = services()
    svc.full_reset()
    return jsonify({"status": "reset", "meshState": svc.mesh.state()})


# --------------------------------------------------------------------------
# THE production endpoint
# --------------------------------------------------------------------------

@bp.route("/api/bridge/ingest", methods=["POST"])
def bridge_ingest():
    """
    The real endpoint a physical bridge phone would call after getting
    internet again. Headers (optional, informational only in this demo,
    same as the Java version):
        X-Bridge-Node-Id: phone-bridge-42
        X-Hop-Count: 3
    Body: MeshPacket JSON, e.g.
        {"packetId": "...", "ttl": 2, "createdAt": 1730000000000, "ciphertext": "base64..."}
    """
    svc = services()
    body = request.get_json(force=True)
    try:
        packet = MeshPacket.from_wire_dict(body)
    except (KeyError, ValueError, TypeError) as exc:
        return jsonify({
            "outcome": "INVALID",
            "packetHash": None,
            "reason": f"MALFORMED_PACKET: {exc}",
            "transactionId": None,
        }), 400

    result = svc.bridge_ingestion.ingest(packet)
    return jsonify(result.to_dict())