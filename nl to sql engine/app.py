import sqlite3
import threading
import time
import re
import json
import os
from typing import Any, Dict, List, Optional, Tuple

# --- Optional Postgres support (install psycopg2-binary if you want to test) ---
try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG = True
except Exception:
    HAS_PSYCOPG = False

# --- Config ---
SCHEMA_REFRESH_SEC = 10
PAGE_SIZE = 100
AUDIT_LOG = "nlq_audit.log"
MAX_ROWS = 5000

# --- Utilities ---
def now_ts():
    return int(time.time())

# --- Adapters ---
class DBAdapter:
    def introspect_schema(self) -> Dict[str, Any]:
        raise NotImplementedError
    def explain(self, sql: str) -> Any:
        raise NotImplementedError
    def execute(self, sql: str, params: Optional[Tuple]=None, limit: Optional[int]=None) -> Tuple[List[Dict], List[str]]:
        raise NotImplementedError

class SQLiteAdapter(DBAdapter):
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def introspect_schema(self):
        cur = self.conn.cursor()
        cur.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view');")
        out = {}
        for r in cur.fetchall():
            name = r["name"]
            if name.startswith("sqlite_"):
                continue
            cols = []
            for c in self.conn.execute(f"PRAGMA table_info('{name}')").fetchall():
                cols.append({"name": c[1], "type": c[2]})
            out[name] = {"columns": cols}
        return out

    def explain(self, sql: str):
        try:
            cur = self.conn.execute("EXPLAIN QUERY PLAN " + sql)
            return [tuple(r) for r in cur.fetchall()]
        except Exception as e:
            return {"error": str(e)}

    def execute(self, sql: str, params=None, limit=None):
        if limit is None:
            limit = MAX_ROWS
        if re.match(r'^\s*select\b', sql, flags=re.I):
            if not re.search(r'\blimit\b', sql, flags=re.I):
                sql = sql.rstrip(';') + f" LIMIT {limit};"
        cur = self.conn.cursor()
        cur.execute(sql, params or ())
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        return [dict(zip(cols, row)) for row in rows], cols

class PostgresAdapter(DBAdapter):
    def __init__(self, dsn: str):
        if not HAS_PSYCOPG:
            raise RuntimeError("psycopg2 not installed; pip install psycopg2-binary")
        self.dsn = dsn
        self.conn = psycopg2.connect(dsn)
        self.conn.autocommit = True

    def introspect_schema(self):
        q = """
        SELECT table_schema, table_name, column_name, data_type
        FROM information_schema.columns
        WHERE table_schema NOT IN ('pg_catalog','information_schema');
        """
        cur = self.conn.cursor()
        cur.execute(q)
        schema = {}
        for schema_name, table_name, column_name, data_type in cur.fetchall():
            key = f"{schema_name}.{table_name}"
            schema.setdefault(key, {"columns": []})["columns"].append({"name": column_name, "type": data_type})
        return schema

    def explain(self, sql: str):
        cur = self.conn.cursor()
        cur.execute("EXPLAIN " + sql)
        return [r[0] for r in cur.fetchall()]

    def execute(self, sql: str, params=None, limit=None):
        if limit is None:
            limit = MAX_ROWS
        if re.match(r'^\s*select\b', sql, flags=re.I) and not re.search(r'\blimit\b', sql, flags=re.I):
            sql = sql.rstrip(';') + f" LIMIT {limit};"
        cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params or ())
        rows = cur.fetchall()
        cols = list(rows[0].keys()) if rows else []
        return [dict(r) for r in rows], cols

# --- Schema manager (background refresh) ---
class SchemaManager:
    def __init__(self, adapter: DBAdapter, refresh_sec: int = SCHEMA_REFRESH_SEC):
        self.adapter = adapter
        self._cache: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self.refresh_sec = refresh_sec
        self._stop = False
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def _loop(self):
        while not self._stop:
            try:
                self.refresh()
            except Exception as e:
                print("schema refresh error:", e)
            time.sleep(self.refresh_sec)

    def stop(self):
        self._stop = True

    def refresh(self):
        s = self.adapter.introspect_schema()
        with self._lock:
            self._cache = s
        print(f"[{time.ctime()}] Schema refreshed ({len(s)} objects)")

    def get_snippet(self, tables: Optional[List[str]] = None, max_chars: int = 2000) -> str:
        with self._lock:
            s = self._cache
            parts = []
            if tables:
                for t in tables:
                    if t in s:
                        cols = ", ".join([c["name"] for c in s[t]["columns"]])
                        parts.append(f"table: {t} cols: {cols}")
            else:
                for t, meta in list(s.items())[:10]:
                    cols = ", ".join([c["name"] for c in meta["columns"]])
                    parts.append(f"table: {t} cols: {cols}")
            return "\n".join(parts)[:max_chars]

# --- Security (RBAC + masking) ---
class SecurityManager:
    def __init__(self):
        # Simple role -> allowed tables + mask rules
        self.policies = {
            "analyst": {"tables": ["customers", "orders"], "mask_columns": {"customers": ["ssn"]}},
            "viewer": {"tables": ["customers"], "mask_columns": {"customers": ["ssn", "email"]}},
            "admin": {"tables": ["*"], "mask_columns": {}},
        }

    def authorize(self, user: Dict[str,Any], tables: List[str]) -> bool:
        role = user.get("role", "viewer")
        policy = self.policies.get(role, {})
        allowed = policy.get("tables", [])
        if "*" in allowed:
            return True
        for t in tables:
            if t not in allowed:
                return False
        return True

    def mask(self, user: Dict[str,Any], table: str, rows: List[Dict]) -> List[Dict]:
        role = user.get("role", "viewer")
        mask_cols = self.policies.get(role, {}).get("mask_columns", {})
        to_mask = mask_cols.get(table, [])
        if not to_mask:
            return rows
        out = []
        for r in rows:
            rr = r.copy()
            for c in to_mask:
                if c in rr:
                    rr[c] = "[REDACTED]"
            out.append(rr)
        return out

# --- SQL validation ---
class SQLValidationError(Exception):
    pass

class SQLValidator:
    DANGEROUS = re.compile(r'\b(drop|delete|truncate|alter|create\s+table|attach|detach|pragma)\b', re.I)
    @classmethod
    def validate(cls, sql: str, allow_non_select: bool = False):
        if cls.DANGEROUS.search(sql) and not allow_non_select:
            raise SQLValidationError("Destructive or DDL statements not allowed.")
        if sql.strip().count(';') > 1:
            raise SQLValidationError("Multiple statements not allowed.")
        if not allow_non_select and not re.match(r'^\s*select\b', sql, flags=re.I):
            raise SQLValidationError("Only SELECT queries are allowed by default.")

# --- Audit logger ---
class Audit:
    def __init__(self, path=AUDIT_LOG):
        self.path = path

    def record(self, user, nl, sql, decision, rows, duration):
        entry = {
            "ts": now_ts(),
            "user": {"id": user.get("id"), "role": user.get("role")},
            "nl": nl,
            "sql": sql,
            "decision": decision,
            "rows": rows,
            "duration_s": duration
        }
        line = json.dumps(entry)
        with open(self.path, "a") as f:
            f.write(line + "\n")
        print("AUDIT:", line)

# --- Dummy LLM (replace with real LLM client) ---
class DummyLLM:
    def generate(self, nl: str, schema_snippet: str, user_ctx: Dict[str,Any]) -> Dict[str,Any]:
        nl_l = nl.lower()
        # pick a table from snippet heuristically
        m = re.search(r'table:\s*(\w+)', schema_snippet)
        table = m.group(1) if m else "customers"
        if "count" in nl_l or "how many" in nl_l:
            return {"sql": f"SELECT COUNT(*) AS cnt FROM {table};", "explain": "count", "confidence": 0.3}
        if "list" in nl_l or "show" in nl_l or "give me" in nl_l:
            return {"sql": f"SELECT * FROM {table} LIMIT {PAGE_SIZE};", "explain": "list", "confidence": 0.3}
        # fallback return a safe no-op
        return {"sql": f"SELECT * FROM {table} LIMIT 10;", "explain": "fallback", "confidence": 0.1}

# --- Main Engine ---
class NLQEngine:
    def __init__(self, adapter: DBAdapter, schema_mgr: SchemaManager, llm: DummyLLM, security: SecurityManager, audit: Audit):
        self.adapter = adapter
        self.schema = schema_mgr
        self.llm = llm
        self.security = security
        self.audit = audit

    def _tables_from_sql(self, sql: str) -> List[str]:
        found = re.findall(r'from\s+([`"]?)(\w+)\1', sql, flags=re.I)
        return [t[1] for t in found]

    def ask(self, user: Dict[str,Any], natural_language: str, relevant_tables: Optional[List[str]] = None, page_size: int = PAGE_SIZE) -> Dict[str,Any]:
        t0 = time.time()
        schema_snip = self.schema.get_snippet(relevant_tables)
        # 1) LLM -> SQL
        llm_out = self.llm.generate(natural_language, schema_snip, {"user": user})
        sql = llm_out.get("sql", "-- no sql")
        # 2) validate
        SQLValidator.validate(sql, allow_non_select=False)
        # 3) extract tables & authorize
        tables = self._tables_from_sql(sql)
        if not self.security.authorize(user, tables):
            raise PermissionError("Access denied to requested tables.")
        # 4) explain (adapter)
        plan = self.adapter.explain(sql)
        # 5) execute (respect page_size)
        rows, cols = self.adapter.execute(sql, params=None, limit=page_size)
        dur = time.time() - t0
        # 6) masking
        masked = rows
        if tables:
            masked = self.security.mask(user, tables[0], rows)
        # 7) audit
        self.audit.record(user, natural_language, sql, {"explain": llm_out.get("explain"), "confidence": llm_out.get("confidence")}, rows=len(rows), duration=dur)
        return {"sql": sql, "plan": plan, "columns": cols, "rows": masked, "duration_s": dur}

# --- Demo / Usage ---
def create_demo_sqlite(path="demo.db"):
    if os.path.exists(path):
        return
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE customers(id INTEGER PRIMARY KEY, name TEXT, email TEXT, ssn TEXT);")
    cur.execute("CREATE TABLE orders(id INTEGER PRIMARY KEY, customer_id INTEGER, total REAL);")
    cur.execute("INSERT INTO customers(name,email,ssn) VALUES ('Alice','alice@example.com','111-22-3333');")
    cur.execute("INSERT INTO customers(name,email,ssn) VALUES ('Bob','bob@example.com','222-33-4444');")
    cur.execute("INSERT INTO orders(customer_id,total) VALUES (1, 19.99);")
    conn.commit()
    conn.close()

def main_demo():
    # build demo sqlite db
    create_demo_sqlite("demo.db")
    # pick adapter (SQLite)
    adapter = SQLiteAdapter("demo.db")
    # optional: PostgreSQL example:
    # adapter = PostgresAdapter("postgresql://user:pass@host:5432/dbname")  # requires psycopg2
    schema_mgr = SchemaManager(adapter, refresh_sec=5)
    llm = DummyLLM()
    security = SecurityManager()
    audit = Audit()
    engine = NLQEngine(adapter, schema_mgr, llm, security, audit)

    user = {"id": "user-1", "role": "analyst"}  # try 'viewer' or 'admin' to test policies
    time.sleep(1)  # give initial refresh a moment

    queries = [
        "List customers",
        "How many orders are there?",
        "Give me customers and their emails"
    ]
    for q in queries:
        try:
            out = engine.ask(user, q, relevant_tables=["customers", "orders"], page_size=10)
            print("NL:", q)
            print("SQL:", out["sql"])
            print("ROWS:", out["rows"])
            print("PLAN:", out["plan"])
            print("-" * 40)
        except Exception as e:
            print("Error for query:", q, "->", e)

    # stop schema background thread gracefully (demo)
    schema_mgr.stop()

if __name__ == "__main__":
    main_demo()



# query runner 

import streamlit as st
# If you are using OpenAI or Gemini, import their client here
# from openai import OpenAI  # Example
# client = OpenAI(api_key="YOUR_API_KEY")

# --- Define the NL to SQL converter ---
def convert_to_sql(query):
    """
    Convert natural language query to SQL.
    For now, this is a placeholder that generates a simple SELECT query.
    Replace with actual NL→SQL logic.
    """
    # Example simple conversion
    table_name = "my_table"  # Change as per your DB
    sql = f"SELECT * FROM {table_name} WHERE column LIKE '%{query}%';"
    return sql

# --- Streamlit UI ---
st.title("🧠 Natural Language to SQL")
query = st.text_input("Enter your natural language query:")

if st.button("Convert to SQL"):
    if query.strip():
        sql = convert_to_sql(query)
        st.code(sql, language="sql")
    else:
        st.warning("Please enter a query.")

# to store in database  import sqlite3
import os

# Create database & table if not exists
DB_PATH = "queries.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nl_query TEXT NOT NULL,
            sql_query TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Function to save query to database
def save_query(nl_query, sql_query):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO query_log (nl_query, sql_query) VALUES (?, ?)", (nl_query, sql_query))
    conn.commit()
    conn.close()

# --- Define the NL to SQL converter ---
def convert_to_sql(query):
    """
    Convert natural language query to SQL.
    For now, this is a placeholder that generates a simple SELECT query.
    Replace with actual NL→SQL logic.
    """
    table_name = "my_table"  # Change as per your DB
    sql = f"SELECT * FROM {table_name} WHERE column LIKE '%{query}%';"
    return sql

