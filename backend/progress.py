from typing import Dict, Set
from fastapi import WebSocket

class ProgressManager:
    def __init__(self):
        self.connections: Dict[int, Set[WebSocket]] = {}

    async def connect(self, inspection_id: int, websocket: WebSocket):
        await websocket.accept()
        self.connections.setdefault(inspection_id, set()).add(websocket)

    def disconnect(self, inspection_id: int, websocket: WebSocket):
        self.connections.get(inspection_id, set()).discard(websocket)

    async def send(self, inspection_id: int, message: str):
        for ws in list(self.connections.get(inspection_id, set())):
            try:
                await ws.send_json({"message": message})
            except Exception:
                self.disconnect(inspection_id, ws)

progress_manager = ProgressManager()
