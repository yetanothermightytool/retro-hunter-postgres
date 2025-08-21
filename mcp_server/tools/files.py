from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
import psycopg2
import os
from dotenv import load_dotenv
import datetime

load_dotenv()

router = APIRouter(prefix="/files", tags=["Files"])

def get_pg_conn():
   return psycopg2.connect(
       host=os.getenv("POSTGRES_HOST", "db"),
       port=os.getenv("POSTGRES_PORT", "5432"),
       dbname=os.getenv("POSTGRES_DB"),
       user=os.getenv("POSTGRES_USER"),
       password=os.getenv("POSTGRES_PASSWORD")
   )

@router.get("/kpis")
def get_kpis():
   try:
       conn = get_pg_conn()
       cur = conn.cursor()
       cur.execute("""
           SELECT
               (SELECT COUNT(*) FROM files) AS total_files,
               (SELECT COUNT(DISTINCT f.sha256)
               FROM files f
               JOIN malwarebazaar mb ON f.sha256 = mb.sha256) AS malware_hits,
               (SELECT COUNT(DISTINCT f.sha256)
               FROM files f
               JOIN lolbas l ON f.sha256 = l.sha256) AS lolbas_hits,
               (SELECT COUNT(DISTINCT f.path)
               FROM files f
               JOIN scan_findings s ON f.sha256 = s.sha256
               WHERE LOWER(s.detection) LIKE '%yara%') AS yara_hits
       """)
       row = cur.fetchone()
       cur.close()
       conn.close()

       if not row:
           return JSONResponse(status_code=200, content={"results": []})

       return JSONResponse(content={
           "results": [{
               "malware_hits": row[0],
               "yara_hits": row[1],
               "lolbas_hits": row[2],
               "total_files": row[3]
           }]
       })

   except Exception as e:
       return JSONResponse(status_code=500, content={"error": str(e)})

@router.get("/files/malwarebazaar-hits", tags=["Files"])
def get_malwarebazaar_hits(hostname: str = Query(None)):
   try:
       conn = get_pg_conn()
       cur = conn.cursor()

       if hostname:
           cur.execute("""
               SELECT f.hostname, f.filename, f.path, f.sha256
               FROM files f
               JOIN malwarebazaar mb ON f.sha256 = mb.sha256
               WHERE f.hostname = %s
           """, (hostname,))
       else:
           cur.execute("""
               SELECT f.hostname, f.filename, f.path, f.sha256
               FROM files f
               JOIN malwarebazaar mb ON f.sha256 = mb.sha256
           """)

       rows = cur.fetchall()
       cur.close()
       conn.close()

       results = [
           {
               "hostname": row[0],
               "filename": row[1],
               "path": row[2],
               "sha256": row[3]
           }
           for row in rows
       ]

       return JSONResponse(status_code=200, content={"results": results})

   except Exception as e:
       return JSONResponse(status_code=500, content={"error": str(e)})

@router.get("/files/suspicious-pe", tags=["Files"])
def suspicious_pe_files(hostname: str = Query(None)):
   try:
       conn = get_pg_conn()
       cur = conn.cursor()

       query = """
           SELECT hostname, filename, path, sha256, ROUND(entropy::numeric, 2) AS entropy,
                  magic_type, pe_timestamp, pe_sections
           FROM files
           WHERE filetype = 'executable'
             AND entropy > 7.5
             AND pe_timestamp IS NOT NULL
       """

       params = []
       if hostname:
           query += " AND hostname = %s"
           params.append(hostname)

       query += " ORDER BY entropy DESC LIMIT 100"

       cur.execute(query, tuple(params))
       rows = cur.fetchall()
       cur.close()
       conn.close()

       if not rows:
           return JSONResponse(status_code=200, content={"results": []})

       result = []
       for row in rows:
           result.append({
               "hostname": row[0],
               "filename": row[1],
               "path": row[2],
               "sha256": row[3],
               "entropy": float(row[4]),
               "magic_type": row[5],
               "pe_timestamp": row[6].isoformat() if isinstance(row[6], datetime.datetime) else row[6],
               "pe_sections": row[7]
           })

       return JSONResponse(content={"results": result})

   except Exception as e:
       return JSONResponse(status_code=500, content={"error": str(e)})

def register_tool(app):
   app.include_router(router)

