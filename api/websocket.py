"""
NIDS — WebSocket Real-time Streaming
====================================
WebSocket endpoints for real-time event streaming and live metrics.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any
from collections import defaultdict

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

logger = logging.getLogger("NIDS.WebSocket")


class ConnectionManager:
    """Manages WebSocket connections and message broadcasting."""
    
    def __init__(self):
        # Connections grouped by channel
        self.connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, channel: str = "events"):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self.connections[channel].add(websocket)
        logger.info(f"WebSocket connected to channel '{channel}'. Total: {len(self.connections[channel])}")
    
    async def disconnect(self, websocket: WebSocket, channel: str = "events"):
        """Remove a WebSocket connection."""
        async with self._lock:
            self.connections[channel].discard(websocket)
        logger.info(f"WebSocket disconnected from channel '{channel}'. Total: {len(self.connections[channel])}")
    
    async def broadcast(self, message: dict[str, Any], channel: str = "events"):
        """Broadcast a message to all connections in a channel."""
        if not self.connections[channel]:
            return
        
        message_json = json.dumps(message, default=str)
        disconnected = []
        
        async with self._lock:
            for websocket in self.connections[channel].copy():
                try:
                    if websocket.client_state == WebSocketState.CONNECTED:
                        await websocket.send_text(message_json)
                except Exception as e:
                    logger.warning(f"Failed to send to websocket: {e}")
                    disconnected.append(websocket)
            
            # Clean up disconnected websockets
            for ws in disconnected:
                self.connections[channel].discard(ws)
    
    async def send_personal(self, websocket: WebSocket, message: dict[str, Any]):
        """Send a message to a specific connection."""
        try:
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_text(json.dumps(message, default=str))
        except Exception as e:
            logger.warning(f"Failed to send personal message: {e}")
    
    def get_connection_count(self, channel: str = "events") -> int:
        """Get the number of active connections in a channel."""
        return len(self.connections.get(channel, set()))
    
    def get_all_connection_counts(self) -> dict[str, int]:
        """Get connection counts for all channels."""
        return {channel: len(conns) for channel, conns in self.connections.items()}


# Global connection manager
manager = ConnectionManager()


async def handle_events_websocket(websocket: WebSocket):
    """Handle WebSocket connection for real-time event streaming."""
    await manager.connect(websocket, "events")
    
    try:
        # Send initial connection confirmation
        await manager.send_personal(websocket, {
            "type": "connected",
            "channel": "events",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Connected to NIDS event stream"
        })
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for any client messages (ping/pong, commands)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                
                # Handle client commands
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await manager.send_personal(websocket, {
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                except json.JSONDecodeError:
                    pass
                    
            except asyncio.TimeoutError:
                # Send keepalive ping
                await manager.send_personal(websocket, {
                    "type": "ping",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await manager.disconnect(websocket, "events")


async def handle_metrics_websocket(websocket: WebSocket):
    """Handle WebSocket connection for real-time metrics streaming."""
    await manager.connect(websocket, "metrics")
    
    try:
        await manager.send_personal(websocket, {
            "type": "connected",
            "channel": "metrics",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Connected to NIDS metrics stream"
        })
        
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await manager.send_personal(websocket, {
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                except json.JSONDecodeError:
                    pass
            except asyncio.TimeoutError:
                await manager.send_personal(websocket, {
                    "type": "ping",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Metrics WebSocket error: {e}")
    finally:
        await manager.disconnect(websocket, "metrics")


async def broadcast_event(event_data: dict[str, Any]):
    """Broadcast a detection event to all connected clients."""
    message = {
        "type": "event",
        "data": event_data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await manager.broadcast(message, "events")


async def broadcast_metrics(metrics_data: dict[str, Any]):
    """Broadcast metrics update to all connected clients."""
    message = {
        "type": "metrics",
        "data": metrics_data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await manager.broadcast(message, "metrics")


async def broadcast_alert(alert_data: dict[str, Any]):
    """Broadcast a critical alert to all connected clients."""
    message = {
        "type": "alert",
        "data": alert_data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    # Send to both channels for high-priority alerts
    await manager.broadcast(message, "events")
    await manager.broadcast(message, "metrics")
