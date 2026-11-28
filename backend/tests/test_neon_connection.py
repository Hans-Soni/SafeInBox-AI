"""Test direct connection to Neon PostgreSQL."""

import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import engine
from sqlalchemy import text


async def test_conn():
    print("[*] Connecting to database...")
    async with engine.connect() as conn:
        if engine.dialect.name == "sqlite":
            result = await conn.execute(text("SELECT sqlite_version();"))
            ver = f"SQLite {result.scalar()}"
        else:
            result = await conn.execute(text("SELECT version();"))
            ver = result.scalar()
        print(f"[OK] Successfully connected!")
        print(f"     Database Version: {ver}")

        if engine.dialect.name != "sqlite":
            res_tables = await conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema='public';"))
            tables = [r[0] for r in res_tables.fetchall()]
            print(f"     Existing public tables ({len(tables)}): {tables}")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(test_conn())

