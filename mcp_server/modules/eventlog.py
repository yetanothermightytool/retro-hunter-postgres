from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def register_modules(app):
   router = APIRouter(tags=["Event Logs"])

   def get_pg_conn():
       return psycopg2.connect(
           host=os.getenv("POSTGRES_HOST", "db"),
           port=os.getenv("POSTGRES_PORT", "5432"),
           dbname=os.getenv("POSTGRES_DB"),
           user=os.getenv("POSTGRES_USER"),
           password=os.getenv("POSTGRES_PASSWORD")
       )

   @router.get("/events")
   def get_events(hostname: str = Query(...), limit: int = Query(50, le=500)):
       try:
           conn = get_pg_conn()
           cur = conn.cursor()
           cur.execute("""
               SELECT event_id, level, timestamp, source, message
               FROM win_events
               WHERE hostname = %s
               ORDER BY timestamp DESC
               LIMIT %s
           """, (hostname, limit))
           rows = cur.fetchall()
           cur.close()
           conn.close()

           result = [
               {
                   "event_id": row[0],
                   "level": row[1],
                   "timestamp": row[2],
                   "source": row[3],
                   "message": row[4][:300]  # truncate long messages
               }
               for row in rows
           ]
           return JSONResponse(content={"events": result})
       except Exception as e:
           return JSONResponse(status_code=500, content={"error": str(e)})

   app.include_router(router)

