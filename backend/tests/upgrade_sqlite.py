import sqlite3
import os
from datetime import datetime, timezone

now_iso = datetime.now(timezone.utc).isoformat()

for path in ['backend/safeinbox.db', 'safeinbox.db']:
    abs_path = os.path.abspath(path)
    if os.path.exists(abs_path):
        conn = sqlite3.connect(abs_path)
        cur = conn.cursor()
        cols = [c[1] for c in cur.execute('PRAGMA table_info(users)').fetchall()]
        if 'password_changed_at' not in cols:
            cur.execute(f"ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP DEFAULT '{now_iso}'")
        if 'password_history' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN password_history JSON DEFAULT '[]'")
        if 'failed_login_attempts' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
        if 'locked_until' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP")
        conn.commit()
        conn.close()
        print('Updated columns for', abs_path)
