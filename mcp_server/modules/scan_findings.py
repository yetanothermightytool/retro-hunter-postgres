from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
import psycopg2
import os
from dotenv import load_dotenv
from datetime import datetime
from typing import Optional

load_dotenv()

def register_modules(app):
   router = APIRouter(tags=["Scan Findings"])

   def get_pg_conn():
       return psycopg2.connect(
           host=os.getenv("POSTGRES_HOST", "db"),
           port=os.getenv("POSTGRES_PORT", "5432"),
           dbname=os.getenv("POSTGRES_DB"),
           user=os.getenv("POSTGRES_USER"),
           password=os.getenv("POSTGRES_PASSWORD")
       )

   @router.get("/scan-findings", tags=["Scan Findings"])
   def get_scan_findings(
       hostname: str = Query(..., description="Hostname to filter scan results"),
       detection: Optional[str] = Query(None, description="Optional detection string to filter by (e.g. '      malware', 'lolbas')"),
       start_date: Optional[str] = Query(None, description="Filter from this date (YYYY-MM-DD)"),
       end_date: Optional[str] = Query(None, description="Filter up to this date (YYYY-MM-DD)"),
       limit: int = Query(100, le=500, description="Max number of entries to return")
   ):
       try:
           conn = get_pg_conn()
           cur = conn.cursor()

           # Build dynamic WHERE conditions
           conditions = ["hostname = %s"]
           values = [hostname]

           if detection:
               conditions.append("LOWER(detection) LIKE %s")
               values.append(f"%{detection.lower()}%")

           if start_date:
               conditions.append("scanned_at >= %s")
               values.append(start_date)

           if end_date:
               conditions.append("scanned_at <= %s")
               values.append(end_date)

           where_clause = " AND ".join(conditions)
           query = f"""
               SELECT path, sha256, detection, hostname, rp_timestamp, rp_status, scanned_at
               FROM scan_findings
               WHERE {where_clause}
               ORDER BY scanned_at DESC
               LIMIT %s
           """
           values.append(limit)
           cur.execute(query, tuple(values))
           rows = cur.fetchall()
           cur.close()
           conn.close()

           # Convert to JSON-serializable
           result = []
           for row in rows:
               result.append({
                   "path": row[0],
                   "sha256": row[1],
                   "detection": row[2],
                   "hostname": row[3],
                   "rp_timestamp": row[4].isoformat() if isinstance(row[4], datetime) else row[4],
                   "rp_status": row[5],
                   "scanned_at": row[6].isoformat() if isinstance(row[6], datetime) else row[6]
               })

           return JSONResponse(content={"findings": result})

       except Exception as e:
           return JSONResponse(status_code=500, content={"error": str(e)})

   app.include_router(router)
