"""
WebSocket routes for Shadow IT Discovery Bot.
Provides real-time scan status updates via WebSocket.
"""

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from services.ws_manager import get_ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["WebSocket"])


@router.websocket("/api/ws/scan/{scan_id}")
async def scan_status_ws(scan_id: str, websocket: WebSocket):
    """
    WebSocket endpoint for real-time scan status.
    
    Replaces HTTP polling for scan progress.
    Server pushes status updates as JSON:
    ```json
    {"status": "scanning", "progress": 40, "message": "Discovering assets..."}
    ```
    """
    manager = get_ws_manager()
    await manager.connect(scan_id, websocket)

    try:
        # Keep connection alive until client disconnects
        while True:
            # Client pings are received as text messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
        logger.debug("WebSocket disconnected for scan %s", scan_id)
    except Exception as e:
        manager.disconnect(scan_id, websocket)
        logger.debug("WebSocket error for scan %s: %s", scan_id, e)
