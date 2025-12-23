# Linear-PBFT (Collector-Based PBFT)

A Python implementation of **PBFT-style Byzantine Fault Tolerance** for a simple replicated banking datastore (client balances + transfers). This project implements the **normal-case PBFT phases** (Pre-Prepare → Prepare → Commit → Execute/Reply) using a **collector pattern** (replicas send Prepare/Commit to the primary, which then re-broadcasts a quorum certificate), achieving **O(n)** communication per phase instead of PBFT’s classic O(n²).

It also includes **PBFT-style view changes**, **checkpointing**, and a **fault-injection controller** to simulate byzantine behaviors (crash, message drops, equivocation, signature corruption, delays).

---

## Implementation details

### Protocol (replica side)
- **Client Request** handling at the primary (assigns sequence numbers).
- **Pre-Prepare / Prepare / Commit** phases (collector pattern):
  - replicas → primary (votes)
  - primary → all replicas (certificate / aggregated proof)
- **Deterministic execution** of transactions and **signed replies**.
- **Checkpointing** every `CHECKPOINT_INTERVAL` requests, with a **state digest** over balances.
- **View change** (PBFT-style) driven by **progress timeouts** + **exponential backoff**.

### Client side
- Multiple logical clients (**A–J**) that:
  - send requests to the current primary
  - wait for **f+1 matching replies** before considering a request complete
  - retry on timeout, and update their view when they observe higher-view replies

### Runtime & tooling
- **RuntimeManager** spawns each replica as an **independent OS process** and drives test execution.
- Async **TCP transport** with length-prefixed JSON messages.
- A CSV-driven **test orchestrator** for transaction sets and byzantine attack scenarios.
- Interactive debug commands after each set (`printdb`, `printlog`, `printstatus`, `printview`).

---

## Quick start

### 1) Setup
```bash
pip install -r requirements.txt
```

### 2) Run the system
```bash
python main.py --config config.json --tests Testcases.csv
```

The runner is interactive:
- press **ENTER** to start each test set
- after each set, use the command prompt to inspect state/logs, or type `next`

---

## Interactive commands (after each test set)

- `printdb <node_id>`  
  Prints the balance datastore for a node (e.g., `printdb n1`)

- `printlog <node_id>`  
  Prints log entries and their statuses for a node (e.g., `printlog n3`)

- `printstatus <seq>`  
  Aggregated status for a sequence number across all replicas

- `printview`  
  Shows view-change / new-view evidence aggregated across nodes

- `next`  
  Continue to the next test set

---

## Configuration

### `config.json`
Defines the nodes/clients and runtime settings.

- `nodes`: `[{ "id": "n1", "host": "localhost", "port": 5001 }, ...]`
- `clients`: `[{ "id": "A", "port": 6001 }, ...]`
- `fault_tolerance`: intended f value(in this project, it is set to handle 2 node failures.)
- `initial_balance`: initial balance assigned to clients A–J

### `src/constants.py`
Protocol-level constants:
- `F`, `N` (defaults: `F=2`, `N=7`)
- Quorum sizes:
  - `QUORUM_PREPARE = N - F`
  - `QUORUM_COMMIT  = N - F`
  - `QUORUM_REPLY   = F + 1`
  - `QUORUM_VIEWCHANGE = 2F + 1`
- `CHECKPOINT_INTERVAL`, view-change backoff parameters, etc.

If you want to change the cluster size and no.of node failures, update **both** `src/constants.py` and `config.json`.

---

## CSV test format

`Testcases.csv` is parsed by `tests/test_orchestrator.py`.

Each test set can define:
- **Transactions**:
  - `(A, B, 5)` → transfer 5 from A to B
  - `(E)` → balance check for E (read-only)
- **Live nodes**: e.g. `[n1, n2, n3, ...]`
- **Byzantine nodes**: e.g. `[n4]`
- **Attack**: a dictionary-like description of the fault to inject (see next section)

---

## Fault injection (Byzantine behaviors)

Each node process exposes a small **control channel** used by the runtime to:
- mark nodes active/inactive
- configure byzantine behavior for selected nodes
- pause timers, flush state, and fetch logs/status snapshots

Supported byzantine knobs live in `nodes/byzantine_faults.py` and are applied in `runtime/node_process.py`, including:
- crash / stop participating
- drop messages to specific peers
- introduce delays (timing attacks)
- corrupt signatures
- equivocate Pre-Prepare (forge sequence numbers)

These are used to validate safety/liveness behavior under adverse conditions.

---

## Project layout

- `main.py` — entry point
- `runtime/manager.py` — orchestrates processes, runs test sets, interactive commands
- `runtime/node_process.py` — per-replica process entry + TCP servers + fault controller
- `nodes/protocol_linear_pbft.py` — normal-case protocol (collector-based)
- `nodes/view_change.py` — PBFT-style view change logic + timeouts/backoff
- `nodes/replica.py` — deterministic application state (balances) + log + checkpoints
- `clients/client.py` — client request/retry + reply quorum logic
- `network/transport.py` — asyncio TCP message framing + send/recv
- `src/message.py` — message types + (de)serialization + signing
- `src/crypto.py` — Ed25519 signatures + hashing + key registry
- `tests/test_orchestrator.py` — CSV parsing into test sets
- `utils/printer.py` — printdb/printlog/printstatus/printview helpers

---

## Notes / limitations

- The system is designed around a fixed default of **N=7, f=2**; changing cluster size requires updating constants and config together.
- Persistence is in-memory; restarting processes resets state.

---
