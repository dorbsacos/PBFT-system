"""
Runtime manager for Linear-PBFT system.
This version runs replicas in independent OS processes and keeps the
client driver / orchestrator in the main process.
"""

import asyncio
import contextlib
import json
import multiprocessing as mp
import logging
from typing import Dict, Any, Optional, List, Tuple, Set

from src.config_loader import load_config
from src.crypto import generate_all_keypairs, CryptoManager, PublicKeyRegistry
from src.constants import NODE_IDS, CLIENT_IDS, MSG_REQUEST, CONTROL_PORT_OFFSET
from src.constants import TXN_TRANSFER, TXN_BALANCE
from clients.client_driver import ClientDriver
from tests.test_orchestrator import TestOrchestrator, Transaction
from utils.logger import create_logger
from network.transport import send_message, start_server
from runtime.node_process import start_node_process
from src.message import Message
from utils.printer import print_db, print_status, print_view, print_log


class RuntimeManager:
    """Coordinates configuration, cryptography, client driver, and tests."""

    def __init__(self, config_path: str, test_csv: str):
        self.config_path = config_path
        self.test_csv = test_csv
        self.logger = create_logger("RuntimeManager")
        self.logger.setLevel(logging.WARNING)
        logging.getLogger("transport").setLevel(logging.INFO)

        self.config: Dict[str, Any] = {}
        self.node_endpoints: Dict[str, tuple[str, int]] = {}
        self.client_endpoints: Dict[str, tuple[str, int]] = {}

        self.node_private_keys: Dict[str, bytes] = {}
        self.node_public_keys: Dict[str, bytes] = {}
        self.client_private_keys: Dict[str, CryptoManager] = {}
        self.client_public_keys: Dict[str, bytes] = {}

        self.client_driver: Optional[ClientDriver] = None
        self.test_orchestrator = TestOrchestrator(logger=create_logger("TestOrchestrator"))

        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.client_servers = []

        self.node_processes: list[mp.Process] = []
        self.current_view = 0
        self.active_nodes = set(NODE_IDS)
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._timestamp_counter = 1
        self.monitor_active = False
    def initialize(self):
        self.logger.info("Loading configuration from %s", self.config_path)
        self.config = load_config(self.config_path)

        self.node_endpoints = {
            entry["id"]: (entry["host"], entry["port"])
            for entry in self.config.get("nodes", [])
        }
        self.client_endpoints = {
            entry["id"]: (entry.get("host", "localhost"), entry["port"])
            for entry in self.config.get("clients", [])
        }

        self.logger.info("Generating key pairs for nodes and clients")
        keypairs = generate_all_keypairs(NODE_IDS, CLIENT_IDS)
        for node_id in NODE_IDS:
            crypto, public_bytes = keypairs[node_id]
            self.node_private_keys[node_id] = crypto.serialize_private_key()
            self.node_public_keys[node_id] = public_bytes
        for client_id in CLIENT_IDS:
            crypto, public_bytes = keypairs[client_id]
            self.client_private_keys[client_id] = crypto
            self.client_public_keys[client_id] = public_bytes

        self.logger.info("Spawning node processes")
        self._start_node_processes()

        self.logger.info("Initializing client driver")
        self.client_driver = ClientDriver(
            client_ids=CLIENT_IDS,
            crypto_map=self.client_private_keys,
            public_keys=self._build_public_registry(),
            send_to_primary=self._client_send_to_primary,
            broadcast_to_all=self._client_broadcast,
            logger=create_logger("ClientDriver"),
        )

        self.logger.info("Loading test cases from %s", self.test_csv)
        self.test_orchestrator.load_csv(self.test_csv)

    def _build_public_registry(self):
        registry = PublicKeyRegistry()
        for node_id, key_bytes in self.node_public_keys.items():
            registry.register_public_key_from_bytes(node_id, key_bytes)
        for client_id, key_bytes in self.client_public_keys.items():
            registry.register_public_key_from_bytes(client_id, key_bytes)
        return registry

    def _start_node_processes(self):
        node_public_map = self.node_public_keys
        client_public_map = self.client_public_keys
        for node_id in NODE_IDS:
            private_key_bytes = self.node_private_keys[node_id]
            proc = mp.Process(
                target=start_node_process,
                args=(
                    self.config_path,
                    node_id,
                    private_key_bytes,
                    node_public_map,
                    client_public_map,
                ),
                daemon=True,
            )
            proc.start()
            self.node_processes.append(proc)
    def _control_endpoint(self, node_id: str) -> tuple[str, int]:
        host, port = self.node_endpoints[node_id]
        return host, port + CONTROL_PORT_OFFSET

    async def _control_request(self, node_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        host, port = self._control_endpoint(node_id)
        reader, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(json.dumps(payload).encode("utf-8") + b"\n")
            await writer.drain()
            response_line = await reader.readline()
            if not response_line:
                raise RuntimeError("Empty response from node")
            response = json.loads(response_line.decode("utf-8"))
            if not response.get("ok"):
                raise RuntimeError(response.get("error", "unknown error"))
            return response.get("result")
        finally:
            writer.close()
            await writer.wait_closed()

    def _control_request_sync(self, node_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._control_request(node_id, payload),
                self.loop,
            )
            return future.result(timeout=5)
        except Exception as exc:
            self.logger.error("Control request to %s failed: %s", node_id, exc)
            return None

    async def _control_request_async(self, node_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            return await self._control_request(node_id, payload)
        except Exception as exc:
            self.logger.error("Control request to %s failed: %s", node_id, exc)
            return None

    def _schedule(self, coro):
        if not self.loop:
            raise RuntimeError("Event loop not initialized")
        self.loop.create_task(coro)

    def _client_send_to_primary(self, client_id: str, message):
        primary_id = self._current_primary_id()
        if primary_id not in self.active_nodes:
            primary_id = next(iter(self.active_nodes))
        host, port = self.node_endpoints[primary_id]
        self._schedule(send_message(host, port, message))

    def _client_broadcast(self, message):
        for node_id in self.active_nodes:
            host, port = self.node_endpoints[node_id]
            self._schedule(send_message(host, port, message))

    def _current_primary_id(self) -> str:
        return NODE_IDS[self.current_view % len(NODE_IDS)]
    async def _start_client_servers(self):
        self.loop = asyncio.get_running_loop()
        for client_id, (host, port) in self.client_endpoints.items():
            handler = self._make_client_handler(client_id)
            retries = 5
            while retries > 0:
                try:
                    server = await start_server(host, port, handler, reuse_address=True)
                    self.client_servers.append(server)
                    break
                except OSError as exc:
                    retries -= 1
                    self.logger.warning(
                        "Client listener %s failed to bind on %s:%s (%s). Retrying...",
                        client_id,
                        host,
                        port,
                        exc,
                    )
                    await asyncio.sleep(0.5)
            else:
                raise RuntimeError(f"Client {client_id} failed to bind on {host}:{port}")

    async def _stop_client_servers(self):
        for server in self.client_servers:
            server.close()
            await server.wait_closed()

    def _make_client_handler(self, client_id: str):
        async def handler(message: Message, peer: str):
            self.client_driver.handle_reply(message)
        return handler
    def run(self):
        try:
            asyncio.run(self._async_run())
        finally:
            self._join_node_processes()

    async def _async_run(self):
        await self._start_client_servers()
        self._running = True
        if self.loop:
            self._monitor_task = self.loop.create_task(self._monitor_timeouts())
        try:
            await self._run_tests()
        finally:
            self._running = False
            if self._monitor_task:
                await asyncio.sleep(0)
                self._monitor_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._monitor_task
            await self._stop_client_servers()
            await self._broadcast_control_stop()

    async def _monitor_timeouts(self):
        while self._running:
            if not self.monitor_active:
                await asyncio.sleep(0.1)
                continue
            triggered = self.client_driver.check_timeouts()
            if triggered:
                print(f"[Client retries] {', '.join(triggered)}")
            await asyncio.sleep(0.1)
    async def _run_tests(self):
        print("\nDistributed Banking System - Test Runner")
        print(f"Test File: {self.test_csv}\n")
        print(f"[TestRunner] Parsing {self.test_csv}")
        print(f"[TestRunner] Loaded {len(self.test_orchestrator.test_cases)} test sets\n")
        print("[TestRunner] Initializing system\n")
        print("[TestRunner] Starting nodes")
        for idx, (node_id, (host, port)) in enumerate(self.node_endpoints.items(), start=1):
            print(f"[Node {idx}] Started on {host}:{port}")
        print("[TestRunner] Creating clients")
        print("[ClientManager] Initialized 10 clients\n")
        print("[TestRunner] Ready to run tests")
        print("Press ENTER to start first set")

        for index, test_case in enumerate(self.test_orchestrator.test_cases):
            await self._await_user_prompt(test_case.set_number, first=(index == 0))
            await self._flush_system()
            await self._configure_case(test_case)

            self._print_set_header(test_case)
            self.monitor_active = True

            for txn_index, txn in enumerate(test_case.transactions, start=1):
                await self._execute_transaction(txn_index, txn)

            self.monitor_active = False
            print(f"\n[Set {test_case.set_number}] Complete\n")
            await self._interactive_post_set(test_case.set_number)

        self.monitor_active = False
        print("All test sets completed.\n")

    async def _await_user_prompt(self, set_number: int, first: bool = False):
        prompt = ("" if first else f"\nPress ENTER to start Set {set_number}")
        if self.loop:
            await self.loop.run_in_executor(None, lambda: input(prompt))
        else:
            input(prompt)

    async def _flush_system(self):
        await asyncio.gather(
            *[
                self._control_request(node_id, {"cmd": "flush"})
                for node_id in NODE_IDS
            ]
        )
        self.client_driver.reset()
        self.client_driver.update_view(0)
        self.current_view = 0
        self._timestamp_counter = 1

    async def _configure_case(self, test_case):
        self.active_nodes = set(test_case.live_nodes) if test_case.live_nodes else set(NODE_IDS)
        tasks = []
        attack_payload = test_case.attacks.to_dict()
        crashed_nodes: Set[str] = set()
        if attack_payload.get("crash"):
            crashed_nodes = set(test_case.byzantine_nodes)
        for node_id in NODE_IDS:
            is_crashed = node_id in crashed_nodes
            active = node_id in self.active_nodes and not is_crashed
            if is_crashed and node_id in self.active_nodes:
                self.active_nodes.discard(node_id)
            tasks.append(
                self._control_request(node_id, {"cmd": "set_active", "active": active})
            )
            config_payload = attack_payload if node_id in test_case.byzantine_nodes else {}
            tasks.append(self._control_request(node_id, {"cmd": "configure_attack", "config": config_payload}))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _execute_transaction(self, txn_index: int, txn: Transaction):
        client_id = txn.client_id
        timestamp = self._next_timestamp()
        txn_dict = {
            "client_id": client_id,
            "type": txn.txn_type,
            "sender": txn.sender,
            "receiver": txn.receiver,
            "amount": txn.amount,
        }
        submitted = self.client_driver.submit_transaction(txn_dict, timestamp)
        if not submitted:
            print(f"  [{txn_index}] Transaction rejected before send")
            return
        success, reason = await self._wait_for_completion(client_id, timestamp)
        if success:
            status = "SUCCESS"
        else:
            detail = f" ({reason})" if reason else ""
            status = f"FAILED{detail}"
        if txn.txn_type == TXN_TRANSFER:
            print(f"  [{txn_index}] {txn.sender} -> {txn.receiver} ${txn.amount}: {status}")
        elif txn.txn_type == TXN_BALANCE:
            print(f"  [{txn_index}] {txn.sender} balance check: {status}")
        else:
            print(f"  [{txn_index}] Transaction: {status}")

    async def _wait_for_completion(self, client_id: str, timestamp: int, timeout: float = 30.0) -> Tuple[bool, Optional[str]]:
        loop_time = asyncio.get_running_loop().time()
        start = loop_time
        while True:
            client = self.client_driver.clients[client_id]
            if not client.pending:
                return not client.last_request_failed, client.last_failure_reason
            if client.pending.timestamp != timestamp:
                return not client.last_request_failed, client.last_failure_reason
            if asyncio.get_running_loop().time() - start > timeout:
                self.logger.error(
                    "Timeout waiting for client %s request %s",
                    client_id,
                    timestamp,
                )
                return False, "Timeout waiting for reply"
            await asyncio.sleep(0.1)

    async def _interactive_post_set(self, set_number: int):
        print("Runtime: Resetting all nodes")
        await asyncio.gather(
            *[
                self._control_request(node_id, {"cmd": "pause_timers"})
                for node_id in NODE_IDS
            ],
            return_exceptions=True,
        )
        print("Available commands:")
        print("  printdb <node_id>         - Show database state of a node")
        print("  printlog <node_id>        - Show log entries for a node")
        print("  printstatus <seq>         - Show status of a sequence on all nodes")
        print("  printview                 - Show aggregated view-change data")
        print("  next                      - Continue to next set")
        while True:
            try:
                command = await self.loop.run_in_executor(None, lambda: input("command> ").strip())
            except EOFError:
                command = "next"
            if not command:
                continue
            tokens = command.split()
            cmd = tokens[0].lower()
            if cmd == "printdb":
                if len(tokens) != 2:
                    print("Usage: printdb <node_id>")
                    continue
                node_id = self._normalize_node_id(tokens[1])
                if not node_id:
                    print("Unknown node id", tokens[1])
                    continue
                balances = await self._collect_balances([node_id])
                if balances:
                    print_db(balances)
                else:
                    print(f"Unknown node id {node_id}")
            elif cmd == "printstatus":
                if len(tokens) != 2:
                    print("Usage: printstatus <sequence>")
                    continue
                try:
                    sequence = int(tokens[1])
                except ValueError:
                    print("Sequence must be an integer")
                    continue
                status_map = await self._collect_status(sequence)
                if not status_map:
                    print("No node statuses available")
                    continue
                print_status(sequence, status_map)
            elif cmd == "printview":
                if len(tokens) != 1:
                    print("Usage: printview")
                    continue
                view_snapshot = await self._collect_view_snapshot()
                if not view_snapshot:
                    print("No view data available")
                    continue
                print_view(view_snapshot)
            elif cmd == "printlog":
                if len(tokens) != 2:
                    print("Usage: printlog <node_id>")
                    continue
                node_id = self._normalize_node_id(tokens[1])
                if not node_id:
                    print("Unknown node id", tokens[1])
                    continue
                log_snapshot = await self._collect_log_snapshot(node_id=node_id)
                if log_snapshot:
                    print_log(log_snapshot)
                else:
                    print(f"Unknown node id {node_id}")
            elif cmd == "next":
                break
            else:
                print("Unknown command. Available: printdb <node_id>, printlog <node_id>, printstatus <seq>, printview, next")

    def _next_timestamp(self) -> int:
        ts = self._timestamp_counter
        self._timestamp_counter += 1
        return ts

    def _normalize_node_id(self, node_token: str) -> Optional[str]:
        if node_token in self.node_endpoints:
            return node_token
        if node_token.lower() in self.node_endpoints:
            return node_token.lower()
        if node_token.isdigit():
            idx = int(node_token) - 1
            if 0 <= idx < len(NODE_IDS):
                return NODE_IDS[idx]
        if node_token.lower().startswith("n") and node_token[1:].isdigit():
            idx = int(node_token[1:]) - 1
            if 0 <= idx < len(NODE_IDS):
                return NODE_IDS[idx]
        return None

    async def _broadcast_control_stop(self):
        tasks = []
        for node_id in NODE_IDS:
            tasks.append(self._control_request(node_id, {"cmd": "stop"}))
        await asyncio.gather(*tasks, return_exceptions=True)

    def _join_node_processes(self):
        for proc in self.node_processes:
            if proc.is_alive():
                proc.join(timeout=5)
                if proc.is_alive():
                    proc.terminate()
                    proc.join()
    async def _collect_balances(self, nodes: Optional[List[str]] = None) -> Dict[str, Dict[str, int]]:
        target_nodes = nodes or NODE_IDS
        balances = {}
        for node_id in target_nodes:
            result = await self._control_request_async(node_id, {"cmd": "get_db"})
            if result is not None:
                balances[node_id] = result
        return balances

    async def _collect_status(self, sequence: int, nodes: Optional[List[str]] = None) -> Dict[str, str]:
        target_nodes = nodes or NODE_IDS
        status_map = {}
        for node_id in target_nodes:
            result = await self._control_request_async(node_id, {"cmd": "get_status", "sequence": sequence})
            if result is not None:
                status_map[node_id] = result.get("status", "X")
            else:
                status_map[node_id] = "X"
        return status_map

    async def _collect_log_snapshot(self, node_id: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        nodes = [node_id] if node_id else NODE_IDS
        snapshot = {}
        for nid in nodes:
            result = await self._control_request_async(nid, {"cmd": "get_log"})
            if result is not None:
                entries_raw = result.get("entries", {})
                entries = {
                    int(seq): meta for seq, meta in entries_raw.items()
                }
                snapshot[nid] = {
                    "entries": entries,
                    "meta": result.get("meta", {}),
                }
        return snapshot

    async def _collect_view_snapshot(self, node_id: Optional[str] = None) -> Dict[str, Any]:
        highest_view = self.current_view
        in_view_change = False
        aggregated_viewchange: Dict[int, set[str]] = {}
        aggregated_newview_payloads: Dict[int, Dict[str, Any]] = {}
        aggregate_config: Dict[int, Dict[str, Any]] = {}
        for nid in NODE_IDS:
            result = await self._control_request_async(nid, {"cmd": "get_view"})
            if result is None:
                continue
            highest_view = max(highest_view, result.get("highest_view", self.current_view))
            if result.get("in_view_change"):
                in_view_change = True
            for view, senders in result.get("viewchange_messages", {}).items():
                aggregated_viewchange.setdefault(int(view), set()).update(senders)
            view_details = result.get("newview_details", {})
            for view, detail in view_details.items():
                view_int = int(view)
                if isinstance(detail, dict):
                    signer_id = detail.get("signer_id") or detail.get("payload", {}).get("signer_id")
                    if signer_id:
                        aggregated_newview_payloads.setdefault(view_int, {})[signer_id] = detail
                config_bucket = aggregate_config.setdefault(view_int, {})
                node_meta = config_bucket.setdefault(nid, {})
                node_meta.update({
                    "config": result.get("config", {}),
                })
        viewchange_messages = {
            view: sorted(senders)
            for view, senders in aggregated_viewchange.items()
        }
        return {
            "current_view": self.current_view,
            "highest_view": highest_view,
            "in_view_change": in_view_change,
            "viewchange_messages": viewchange_messages,
            "newview_messages": sorted(aggregated_newview_payloads.keys()),
            "aggregated_newview_details": {
                str(view): payloads
                for view, payloads in aggregated_newview_payloads.items()
            },
            "newview_configs": {
                str(view): config for view, config in aggregate_config.items()
            },
        }

    def _print_set_header(self, test_case):
        print(f"Test Set {test_case.set_number}")
        ordered_ids = sorted(self.active_nodes, key=lambda nid: NODE_IDS.index(nid))
        pretty = [NODE_IDS.index(nid) + 1 for nid in ordered_ids]
        print(f"Live Nodes: {pretty}")
        if test_case.byzantine_nodes:
            byzantine_numbers = sorted(
                NODE_IDS.index(nid) + 1
                for nid in test_case.byzantine_nodes
            )
            print(f"Byzantine Nodes: {byzantine_numbers}")

            attack_parts: List[str] = []
            attacks = test_case.attacks
            if attacks.sign:
                attack_parts.append("sign")
            if attacks.crash:
                attack_parts.append("crash")
            if attacks.time:
                if attacks.time_delay_ms is not None:
                    attack_parts.append(f"time({attacks.time_delay_ms}ms)")
                else:
                    attack_parts.append("time")
            if attacks.dark_destinations:
                destinations = ", ".join(attacks.dark_destinations)
                attack_parts.append(f"dark({destinations})")
            if attacks.equivocation_destinations:
                destinations = ", ".join(attacks.equivocation_destinations)
                attack_parts.append(f"equivocation({destinations})")

            attack_summary = "; ".join(attack_parts) if attack_parts else "none"
            print(f"Attacks: {attack_summary}")
        else:
            print("Byzantine Nodes: []")
            print("Attacks: none")
        print(f"Transactions: {len(test_case.transactions)}")
        leader_id = self._current_primary_id()
        leader_number = NODE_IDS.index(leader_id) + 1
        print(f"Current Primary: Node {leader_number}\n")
