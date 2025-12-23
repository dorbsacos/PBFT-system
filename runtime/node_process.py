"""
Node process entry point for Linear-PBFT replicas.
Each replica runs in its own OS process and communicates via TCP sockets.
"""

import asyncio
import signal
import contextlib
import json
import copy
from typing import Dict, Optional
import logging

from src.config_loader import load_config
from src.crypto import CryptoManager, PublicKeyRegistry
from src.constants import MSG_REQUEST, NODE_IDS, CLIENT_IDS, CONTROL_PORT_OFFSET
from src.message import Message
from network.transport import send_message, start_server
from nodes.node import Node
from nodes.byzantine_faults import ByzantineFaultController
from utils.logger import create_logger


async def _run_node(
    config_path: str,
    node_id: str,
    private_key_bytes: bytes,
    public_key_map: Dict[str, bytes],
    client_public_key_map: Dict[str, bytes],
):
    config = load_config(config_path)
    quiet_logs = config.get("quiet_logs", False)

    node_endpoints = {
        entry["id"]: (entry["host"], entry["port"])
        for entry in config.get("nodes", [])
    }
    client_endpoints = {
        entry.get("id"): (entry.get("host", "localhost"), entry["port"])
        for entry in config.get("clients", [])
    }

    if node_id not in node_endpoints:
        raise ValueError(f"Node {node_id} not found in configuration")

    loop = asyncio.get_running_loop()

    crypto = CryptoManager.load_private_key_from_bytes(private_key_bytes, node_id)
    registry = PublicKeyRegistry()

    for peer_id, key_bytes in public_key_map.items():
        registry.register_public_key_from_bytes(peer_id, key_bytes)
    for client_id, key_bytes in client_public_key_map.items():
        registry.register_public_key_from_bytes(client_id, key_bytes)

    controller = ByzantineFaultController(node_id)
    controller.attach_crypto(crypto)

    async def _send_with_delay(host: str, port: int, message: Message, delay_ms: Optional[int]):
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000.0)
        await send_message(host, port, message)

    def _clone_message(message: Message) -> Message:
        return Message(
            msg_type=message.msg_type,
            payload=copy.deepcopy(message.payload),
            signer_id=message.signer_id,
            signature=bytes(message.signature) if isinstance(message.signature, (bytes, bytearray)) else message.signature,
        )

    def _prepare_outgoing_message(destination_id: str, message: Message) -> Optional[Message]:
        if controller.config.crash or controller.should_drop(destination_id):
            return None
        cloned = _clone_message(message)
        cloned = controller.mutate_message(cloned, destination_id)
        if controller.should_corrupt_signature():
            sig_len = len(cloned.signature) if isinstance(cloned.signature, (bytes, bytearray)) else 64
            cloned.signature = b"\x00" * max(sig_len, 64)
        return cloned

    def send_to_node(target_id: str, message: Message):
        endpoint = node_endpoints.get(target_id)
        if not endpoint:
            return
        prepared = _prepare_outgoing_message(target_id, message)
        if prepared is None:
            return
        host, port = endpoint
        delay = controller.get_delay_ms()
        loop.create_task(_send_with_delay(host, port, prepared, delay))

    def broadcast_to_nodes(message, exclude: Optional[set] = None):
        exclude = exclude or set()
        for target_id in node_endpoints.keys():
            if target_id == node_id:
                continue
            if target_id in exclude:
                continue
            send_to_node(target_id, message)

    def send_to_client(client_id: str, message: Message):
        endpoint = client_endpoints.get(client_id)
        if not endpoint:
            return
        prepared = _prepare_outgoing_message(client_id, message)
        if prepared is None:
            return
        host, port = endpoint
        delay = controller.get_delay_ms()
        loop.create_task(_send_with_delay(host, port, prepared, delay))

    log_level = logging.ERROR
    node_logger = create_logger(f"Node-{node_id}", level=log_level)

    node = Node(
        node_id=node_id,
        config=config,
        crypto=crypto,
        public_keys=registry,
        send_to_node=send_to_node,
        broadcast_to_nodes=broadcast_to_nodes,
        send_to_client=send_to_client,
        logger=node_logger,
    )

    node_active = True
    node_crashed = controller.config.crash

    async def handle_message(message, peer: str):
        if not node_active or node_crashed:
            return
        sender_id = message.signer_id or peer
        is_client = message.msg_type == MSG_REQUEST and sender_id in CLIENT_IDS
        node.handle_incoming_message(message, sender_id, is_client=is_client)

    host, port = node_endpoints[node_id]
    retries = 5
    while retries > 0:
        try:
            server = await start_server(host, port, handle_message, reuse_address=True)
            break
        except OSError as exc:
            node_logger.error("Failed to bind on %s:%s (%s). Retrying...", host, port, exc)
            retries -= 1
            await asyncio.sleep(0.5)
    else:
        raise RuntimeError(f"Node {node_id} failed to bind on {host}:{port}")
    node_logger.info("Node %s listening on %s:%s", node_id, host, port)

    stop_event = asyncio.Event()

    def _handle_stop_signal():
        stop_event.set()

    with contextlib.suppress(NotImplementedError):
        loop.add_signal_handler(signal.SIGTERM, _handle_stop_signal)
        loop.add_signal_handler(signal.SIGINT, _handle_stop_signal)

    async def handle_control(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        nonlocal node_active
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    await _send_control_response(writer, ok=False, error="invalid_json")
                    continue

                cmd = request.get("cmd")
                if cmd == "flush":
                    node.handle_flush()
                    await _send_control_response(writer, ok=True)
                elif cmd == "get_db":
                    await _send_control_response(writer, ok=True, result=node.get_balances())
                elif cmd == "get_status":
                    sequence = request.get("sequence")
                    status = node.get_status(sequence)
                    await _send_control_response(writer, ok=True, result={"status": status})
                elif cmd == "get_view":
                    await _send_control_response(writer, ok=True, result=node.get_view_state())
                elif cmd == "get_log":
                    log_entries = {}
                    for seq, entry in node.replica_state.log.items():
                        log_entries[str(seq)] = {
                            "view": entry.view,
                            "digest": entry.digest,
                            "status": node.get_status(seq),
                            "preprepare_sender": entry.preprepare_sender,
                            "request": copy.deepcopy(entry.request),
                            "pprepared": entry.status_pprepared,
                            "prepared": entry.status_prepared,
                            "committed": entry.status_committed,
                            "executed": entry.status_executed,
                            "prepare_signers": sorted(entry.prepare_signatures.keys()),
                            "commit_signers": sorted(entry.commit_signatures.keys()),
                            "execution_result": copy.deepcopy(entry.execution_result),
                            "events": copy.deepcopy(entry.events),
                        }
                    checkpoint_meta = {
                        "low_water_mark": node.replica_state.low_water_mark,
                        "high_water_mark": node.replica_state.high_water_mark,
                        "stable_checkpoint_sequence": node.replica_state.stable_checkpoint_sequence,
                        "stable_checkpoint_digest": node.replica_state.stable_checkpoint_digest,
                        "stable_checkpoint_signers": sorted(
                            node.replica_state.stable_checkpoint_signatures.keys()
                        ),
                    }
                    await _send_control_response(
                        writer,
                        ok=True,
                        result={"entries": log_entries, "meta": checkpoint_meta},
                    )
                elif cmd == "set_active":
                    node_active = bool(request.get("active", True))
                    await _send_control_response(writer, ok=True)
                elif cmd == "pause_timers":
                    node.pause_timers()
                    await _send_control_response(writer, ok=True)
                elif cmd == "stop":
                    await _send_control_response(writer, ok=True)
                    stop_event.set()
                    break
                elif cmd == "configure_attack":
                    controller.configure_from_dict(request.get("config"))
                    node_crashed = controller.config.crash
                    await _send_control_response(writer, ok=True)
                else:
                    await _send_control_response(writer, ok=False, error="unknown_command")
        finally:
            writer.close()
            await writer.wait_closed()

    control_server = await asyncio.start_server(
        handle_control,
        host,
        port + CONTROL_PORT_OFFSET,
    )

    async def monitor_timeouts():
        while not stop_event.is_set():
            node.check_timeouts()
            await asyncio.sleep(0.1)

    await asyncio.gather(stop_event.wait(), monitor_timeouts())

    server.close()
    await server.wait_closed()
    control_server.close()
    await control_server.wait_closed()
    node_logger.info("Node %s shutting down", node_id)


async def _send_control_response(writer: asyncio.StreamWriter, ok: bool, result=None, error: Optional[str] = None):
    response = {"ok": ok}
    if result is not None:
        response["result"] = result
    if error is not None:
        response["error"] = error
    writer.write(json.dumps(response).encode("utf-8") + b"\n")
    await writer.drain()


def start_node_process(
    config_path: str,
    node_id: str,
    private_key_bytes: bytes,
    public_key_map: Dict[str, bytes],
    client_public_key_map: Dict[str, bytes],
):
    asyncio.run(
        _run_node(
            config_path=config_path,
            node_id=node_id,
            private_key_bytes=private_key_bytes,
            public_key_map=public_key_map,
            client_public_key_map=client_public_key_map,
        )
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run a PBFT replica process")
    parser.add_argument("node_id", choices=NODE_IDS)
    parser.add_argument("config", default="config.json")
    args = parser.parse_args()
    raise SystemExit("Use RuntimeManager to spawn node processes")

