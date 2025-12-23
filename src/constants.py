"""
Constants for Linear-PBFT implementation
"""

# System configuration
F = 2  # Maximum number of Byzantine faults tolerated
N = 7  # Total number of nodes (3f + 1)
MAX_CLIENTS = 10  # Total number of clients
INITIAL_BALANCE = 10  # Initial balance for all clients

# Network ports (will be configured per node/client in config.json)
BASE_NODE_PORT = 5001  # n1 starts here, increments for n2, n3, etc.
BASE_CLIENT_PORT = 6001  # Reserved for clients if needed

# Message types
MSG_REQUEST = "REQUEST"
MSG_PREPREPARE = "PREPREPARE"
MSG_PREPARE = "PREPARE"
MSG_COMMIT = "COMMIT"
MSG_REPLY = "REPLY"
MSG_CHECKPOINT = "CHECKPOINT"
MSG_VIEWCHANGE = "VIEWCHANGE"
MSG_NEWVIEW = "NEWVIEW"
MSG_FLUSH = "FLUSH"

# Transaction types
TXN_BALANCE = "BALANCE"  # Read-only
TXN_TRANSFER = "TRANSFER"  # Read-write

# Status types (for PrintStatus function)
STATUS_PPREPARED = "PP"
STATUS_PREPARED = "P"
STATUS_COMMITTED = "C"
STATUS_EXECUTED = "E"
STATUS_NONE = "X"

# Linear-PBFT quorums
QUORUM_PREPARE = N - F  # Need n-f prepare messages (5 out of 7)
QUORUM_COMMIT = N - F  # Need n-f commit messages (5 out of 7)
QUORUM_VIEWCHANGE = 2 * F + 1  # Need 2f+1 view-change messages (5 out of 7)
QUORUM_REPLY = F + 1  # Client waits for f+1 matching replies (3 out of 7)
QUORUM_READONLY = 2 * F + 1  # Read-only needs 2f+1 matching replies (5 out of 7)

# Timer values (in milliseconds)
TIMER_CLIENT_RETRY = 4000  # Client retransmits if no reply


# Client retry policy
CLIENT_MAX_RETRIES = 3

# View-change exponential backoff
VIEWCHANGE_DELAY_BASE = 1500  # Base delay in milliseconds
VIEWCHANGE_DELAY_MULTIPLIER = 2  # Multiplier for backoff
VIEWCHANGE_DELAY_JITTER = 0.05  # +/- 5% randomized jitter per node

# Checkpointing parameters
CHECKPOINT_INTERVAL = 10  # Number of requests between checkpoints
LOG_HIGH_WATER_DELTA = 2 * CHECKPOINT_INTERVAL  # Sequence window size above low-water mark

# Byzantine attack delays
BYZANTINE_TIMING_DELAY = 200  # Timing attack delay

# Control channel
CONTROL_PORT_OFFSET = 200

# Client and node IDs
CLIENT_IDS = [chr(65 + i) for i in range(MAX_CLIENTS)]  # A, B, C, ..., J
NODE_IDS = [f"n{i}" for i in range(1, N + 1)]  # n1, n2, ..., n7

# View and sequence limits (safety bounds)
MAX_VIEW = 1000
MAX_SEQUENCE = 10000

# Primary selection formula
def get_primary_for_view(view_num):
    """Returns the node ID that should be the primary for a given view"""
    node_index = view_num % N
    return NODE_IDS[node_index]

