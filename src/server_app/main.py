from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, text
from pathlib import Path


DB_URL = "postgresql+psycopg2://monitsys_user:12345@localhost:5432/monitsys"

app = FastAPI(title="Network Monitoring Dashboard")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

engine = create_engine(DB_URL)


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
def get_status():
    query = text("""
        SELECT 
            COUNT(*) AS total_rows,
            COUNT(DISTINCT vlan_id) AS vlan_count,
            MAX(timestamp) AS last_timestamp
        FROM features
    """)

    with engine.connect() as conn:
        row = conn.execute(query).mappings().first()

    return {
        "total_rows": row["total_rows"],
        "vlan_count": row["vlan_count"],
        "last_timestamp": str(row["last_timestamp"]),
    }


@app.get("/api/vlans")
def get_vlans():
    query = text("""
        SELECT DISTINCT vlan_id
        FROM features
        WHERE vlan_id IS NOT NULL
        ORDER BY vlan_id
    """)

    with engine.connect() as conn:
        rows = conn.execute(query).fetchall()

    return [row[0] for row in rows]


@app.get("/api/metrics")
def get_metrics(
    vlan_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    if vlan_id is None:
        query = text("""
            SELECT *
            FROM features
            ORDER BY timestamp DESC
            LIMIT :limit
        """)
        params = {"limit": limit}
    else:
        query = text("""
            SELECT *
            FROM features
            WHERE vlan_id = :vlan_id
            ORDER BY timestamp DESC
            LIMIT :limit
        """)
        params = {"vlan_id": vlan_id, "limit": limit}

    with engine.connect() as conn:
        rows = conn.execute(query, params).mappings().all()

    result = []
    for row in reversed(rows):
        result.append({
            "id": row["id"],
            "timestamp": str(row["timestamp"]),
            "vlan_id": row["vlan_id"],
            "bytes_per_sec": float(row["bytes_per_sec"] or 0),
            "frames_per_sec": float(row["frames_per_sec"] or 0),
            "broadcast_ratio": float(row["broadcast_ratio"] or 0),
            "arp_per_sec": float(row["arp_per_sec"] or 0),
            "active_ip_count": int(row["active_ip_count"] or 0),
            "active_flow_count": int(row["active_flow_count"] or 0),
            "iat_mean": float(row["iat_mean"] or 0),
            "iat_std": float(row["iat_std"] or 0),
            "snmp_in_errors_rate": float(row["snmp_in_errors_rate"] or 0),
            "snmp_out_errors_rate": float(row["snmp_out_errors_rate"] or 0),
            "snmp_discards_rate": float(row["snmp_discards_rate"] or 0),
            "if_oper_status": row["if_oper_status"],
        })

    return result