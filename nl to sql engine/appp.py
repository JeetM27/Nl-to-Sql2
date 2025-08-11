import threading

def apply_schema_changes_later(path="demo.db", delay=10):
    def run():
        time.sleep(delay)
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        print("🔧 Applying schema changes...")

        # 1. Rename email → email_address
        cur.execute("ALTER TABLE customers RENAME COLUMN email TO email_address;")

        # 2. Add customer_segments table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS customer_segments (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER,
                segment_name TEXT,
                FOREIGN KEY(customer_id) REFERENCES customers(id)
            );
        """)

        # 3. Add discount_applied column
        cur.execute("ALTER TABLE orders ADD COLUMN discount_applied REAL;")

        conn.commit()
        conn.close()
        print("✅ Schema changes applied.")
    threading.Thread(target=run, daemon=True).start()

def main_demo():
    create_demo_sqlite("demo.db")
    adapter = SQLiteAdapter("demo.db")
    schema_mgr = SchemaManager(adapter, refresh_sec=5)
    llm = DummyLLM()
    security = SecurityManager()
    audit = Audit()
    engine = NLQEngine(adapter, schema_mgr, llm, security, audit)

    user = {"id": "user-1", "role": "analyst"}

    # 👇 This will simulate schema changes after 10 seconds
    apply_schema_changes_later("demo.db", delay=10)

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
            time.sleep(3)  # wait between queries to allow schema update
        except Exception as e:
            print("Error for query:", q, "->", e)

    schema_mgr.stop()
