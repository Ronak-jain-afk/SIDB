"""
WebSocket connection manager for Shadow IT Discovery Bot.
Manages real-time scan status push to connected clients.
"""

import json
import logging
from typing import Dict, List, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Manages WebSocket connections grouped by scan_id.
    
    Allows broadcasting status updates to all clients
    watching a particular scan.
    """

    def __init__(self):
        self._connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket):
        """Accept a new WebSocket connection for a scan."""
        await websocket.accept()
        if scan_id not in self._connections:
            self._connections[scan_id] = set()
        self._connections[scan_id].add(websocket)
        logger.debug("WebSocket connected for scan %s (%d clients)",
                     scan_id, len(self._connections[scan_id]))

    def disconnect(self, scan_id: str, websocket: WebSocket):
        """Remove a WebSocket connection."""
        if scan_id in self._connections:
            self._connections[scan_id].discard(websocket)
            if not self._connections[scan_id]:
                del self._connections[scan_id]

    async def broadcast(self, scan_id: str, message: dict):
        """Send a message to all clients watching a scan."""
        if scan_id not in self._connections:
            return

        stale = set()
        data = json.dumps(message, default=str)
        for ws in self._connections[scan_id]:
            try:
                await ws.send_text(data)
            except Exception:
                stale.add(ws)

        for ws in stale:
            self.disconnect(scan_id, ws)

    @property
    def active_connections(self) -> int:
        """Total active WebSocket connections."""
        return sum(len(v) for v in self._connections.values())


# Singleton
_ws_manager: WebSocketManager = WebSocketManager()


def get_ws_manager() -> WebSocketManager:
    """Get the WebSocket manager singleton."""
    return _ws_manager
