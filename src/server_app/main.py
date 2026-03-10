from fastapi import FastAPI
from typing import List
from src.common.schemas import FeatureRow

app = FastAPI()


@app.post("/api/v1/features")
async def receive_features(rows: List[FeatureRow]):
    print(f"Received {len(rows)} feature rows")

    if rows:
        vlan_ids = sorted({row.vlan_id for row in rows})
        print(f"VLANs in batch: {vlan_ids}")
        print(f"First row: {rows[0].model_dump()}")

    return {
        "status": "ok",
        "received": len(rows),
    }