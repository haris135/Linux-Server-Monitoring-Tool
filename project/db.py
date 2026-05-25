import pymysql
from config import DB_CFG

def get_conn():
    print("[DB] Connecting with:", DB_CFG)
    return pymysql.connect(
        host=DB_CFG["host"],
        user=DB_CFG["user"],
        password=DB_CFG["password"],
        database=DB_CFG["database"],
        autocommit=True,
        cursorclass=pymysql.cursors.DictCursor  # important for jsonify
    )

def exec_write(sql, params):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
    finally:
        conn.close()

def exec_fetchall(sql, params=None):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()
    finally:
        conn.close()

# -------------------------
# Add this for Flask APIs
# -------------------------
def exec_read(sql, params=None):
    return exec_fetchall(sql, params)

