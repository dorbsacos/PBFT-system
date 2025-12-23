"""
Async TCP transport helpers for Linear-PBFT runtime
"""

import asyncio
import logging
from typing import Awaitable, Callable

from src.message import Message

logger = logging.getLogger("transport")


async def send_message(host: str, port: int, message: Message) -> None:
    """Send a message to (host, port) using length-prefixed framing."""
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except Exception as exc:
        logger.error("Failed to connect to %s:%s: %s", host, port, exc)
        return

    try:
        writer.write(message.to_bytes())
        await writer.drain()
    except Exception as exc:
        logger.error("Failed to send to %s:%s: %s", host, port, exc)
    finally:
        writer.close()
        await writer.wait_closed()


async def start_server(host: str, port: int, on_message: Callable[[Message, str], Awaitable[None]], reuse_address: bool = False):
    """Start a TCP server that decodes length-prefixed messages and invokes on_message."""

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        peer_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        try:
            logger.debug("Accepted connection from %s", peer_str)
            while True:
                length_prefix = await reader.readexactly(4)
                length = int.from_bytes(length_prefix, byteorder="big")
                payload = await reader.readexactly(length)
                msg = Message.from_bytes(length_prefix + payload)
                logger.debug(
                    "Received message type=%s signer=%s from %s",
                    msg.msg_type,
                    msg.signer_id,
                    peer_str,
                )
                await on_message(msg, peer_str)
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            logger.error("Error handling client %s: %s", peer_str, exc)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_client, host, port, reuse_address=reuse_address)
    return server
