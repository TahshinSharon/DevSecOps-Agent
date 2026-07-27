import json
import os
from typing import Any, Dict, List, Optional
import aiosqlite

_db: Optional[aiosqlite.Connection] = None

async def init_db() -> None:
    global _db
    _db = await aiosqlite.connect(os.getenv("DATABASE_PATH", "docker_inspector.db"))
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL")
    await _db.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    await _db.execute("""
    CREATE TABLE IF NOT EXISTS inspections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      host_name TEXT,
      docker_version TEXT,
      scope_json TEXT,
      containers_scanned INTEGER DEFAULT 0,
      issues_found INTEGER DEFAULT 0,
      risk_level TEXT,
      status TEXT DEFAULT 'running',
      result_json TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    await _db.commit()

async def close_db() -> None:
    global _db
    if _db:
        await _db.close()
        _db = None

def conn() -> aiosqlite.Connection:
    if _db is None:
        raise RuntimeError("Database is not initialized")
    return _db

async def create_user(email: str, password_hash: str) -> Dict[str, Any]:
    cur = await conn().execute("INSERT INTO users(email, password_hash) VALUES (?, ?)", (email, password_hash))
    await conn().commit()
    return {"id": cur.lastrowid, "email": email}

async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    cur = await conn().execute("SELECT * FROM users WHERE email=?", (email,))
    row = await cur.fetchone()
    return dict(row) if row else None

async def create_inspection(user_id: int, scope: Dict[str, Any]) -> int:
    cur = await conn().execute(
        "INSERT INTO inspections(user_id, scope_json, status) VALUES (?, ?, 'running')",
        (user_id, json.dumps(scope)),
    )
    await conn().commit()
    return int(cur.lastrowid)

async def update_inspection(inspection_id: int, **fields: Any) -> None:
    allowed = {"host_name", "docker_version", "containers_scanned", "issues_found", "risk_level", "status", "result_json"}
    parts, values = [], []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "result_json" and not isinstance(value, str):
            value = json.dumps(value)
        parts.append(f"{key}=?")
        values.append(value)
    if not parts:
        return
    parts.append("updated_at=CURRENT_TIMESTAMP")
    values.append(inspection_id)
    await conn().execute(f"UPDATE inspections SET {', '.join(parts)} WHERE id=?", values)
    await conn().commit()

async def list_inspections(user_id: int) -> List[Dict[str, Any]]:
    cur = await conn().execute(
        "SELECT id, host_name, docker_version, containers_scanned, issues_found, risk_level, status, created_at FROM inspections WHERE user_id=? ORDER BY id DESC LIMIT 50",
        (user_id,),
    )
    return [dict(row) for row in await cur.fetchall()]

async def get_inspection(user_id: int, inspection_id: int) -> Optional[Dict[str, Any]]:
    cur = await conn().execute("SELECT * FROM inspections WHERE user_id=? AND id=?", (user_id, inspection_id))
    row = await cur.fetchone()
    if not row:
        return None
    item = dict(row)
    item["scope"] = json.loads(item.pop("scope_json") or "{}")
    item["result"] = json.loads(item.pop("result_json") or "{}")
    return item
