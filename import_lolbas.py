#!/usr/bin/env python3
import csv
import psycopg2
import os
from dotenv import load_dotenv

# .env laden
load_dotenv(dotenv_path=".env.local")
CSV_PATH = "lolbin.csv"

def reset_lolbas_table(cur):
   cur.execute("DROP TABLE IF EXISTS lolbas")
   cur.execute("""
       CREATE TABLE lolbas (
           id INTEGER PRIMARY KEY,
           name TEXT,
           standard_path TEXT,
           description TEXT,
           usecase TEXT,
           mitre_id TEXT,
           sha256 TEXT
       )
   """)

def import_lolbas_data(cur):
   inserted = 0
   with open(CSV_PATH, "r", encoding="utf-8", errors="ignore") as csvfile:
       reader = csv.DictReader(csvfile)
       for row in reader:
           cur.execute("""
               INSERT INTO lolbas
               (id, name, standard_path, description, usecase, mitre_id, sha256)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (id) DO NOTHING
           """, (
               row["id"],
               row["name"],
               row["standard_path"],
               row["description"],
               row["usecase"],
               row["mitre_id"],
               row["sha256"]
           ))
           inserted += 1
   print(f"✅ Imported {inserted} LOLBAS entries.")

def main():
   conn = psycopg2.connect(
       host=os.getenv("POSTGRES_HOST", "localhost"),
       port=os.getenv("POSTGRES_PORT", 5432),
       user=os.getenv("POSTGRES_USER"),
       password=os.getenv("POSTGRES_PASSWORD"),
       dbname=os.getenv("POSTGRES_DB")
   )
   cur = conn.cursor()
   reset_lolbas_table(cur)
   import_lolbas_data(cur)
   conn.commit()
   cur.close()
   conn.close()

if __name__ == "__main__":
   main()
