import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
from sqlalchemy import create_engine
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

# PostgreSQL settings from .env
PG_HOST = os.getenv("POSTGRES_HOST", "db")
PG_PORT = os.getenv("POSTGRES_PORT", "5432")
PG_DB = os.getenv("POSTGRES_DB", "retro-hunter")
PG_USER = os.getenv("POSTGRES_USER")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD")

# Create engine
engine = create_engine(
   f"postgresql+psycopg2://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}@{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DB')}"
)

st.set_page_config(page_title="Retro Hunter - Security Analysis Dashboard", layout="wide")

# Def section
def get_pg_conn():
   return psycopg2.connect(
       host=PG_HOST,
       port=PG_PORT,
       dbname=PG_DB,
       user=PG_USER,
       password=PG_PASSWORD
   )

def classify_event_severity(event_id):
   high_ids = {4104, 4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124}
   medium_high_ids = {800, 1102}
   if event_id in high_ids:
       return "High"
   elif event_id in medium_high_ids:
       return "Medium to High"
   return "Low"

def pg_query(query):
   try:
       df = pd.read_sql_query(query, engine)
       return df
   except Exception as e:
       st.warning(f"❌ Query failed: {e}")
       return pd.DataFrame()

def run_analysis_query(title, query):
   try:
       df = pd.read_sql_query(query, engine)
       if df.empty:
           st.info(f"No entries found for: {title}")
       else:
           st.markdown(f"#### {title}")
           st.dataframe(df, use_container_width=True)
   except Exception as e:
       st.warning(f"❌ Query failed: {e}")

def load_files():
   try:
       df = pg_query("SELECT * FROM files")
       if df.empty:
           st.warning("⚠️ Table 'files' is empty or missing.")
       df["hostname"] = df["hostname"].str.strip().str.lower()
       df["rp_timestamp"] = pd.to_datetime(df["rp_timestamp"], errors="coerce")
       df["rp_status"] = df["rp_status"].fillna("unknown")
       df["inserted_at"] = pd.to_datetime(df.get("inserted_at", None), errors="coerce")
       return df
   except Exception as e:
       st.warning(f"⚠️ Could not load files: {e}")
       return pd.DataFrame()

def load_scan_findings():
   try:
       df = pg_query("""
           SELECT path, sha256, detection AS "Detection", hostname, rp_timestamp, rp_status, scanned_at
           FROM scan_findings
       """)
       df["rp_timestamp"] = pd.to_datetime(df["rp_timestamp"], errors="coerce")
       df["scanned_at"] = pd.to_datetime(df["scanned_at"], errors="coerce")
       df["rp_status"] = df["rp_status"].fillna("unknown")
       return df
   except Exception as e:
       st.warning(f"⚠️ Could not load scan findings: {e}")
       return pd.DataFrame()

def load_eventlog_entries():
   try:
       df = pg_query("""
           SELECT hostname AS Host, rp_timestamp AS "RP Timestamp", event_id AS "Event ID",
                  level AS Level, timestamp AS "Event Time", source AS Source, message AS Message
           FROM win_events
           WHERE event_id IN (
               4104, 4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124, 1102, 550, 800
           )
           ORDER BY "Event Time" DESC
           LIMIT 100
       """)
       return df
   except Exception as e:
       st.warning(f"⚠️ Could not load event log entries: {e}")
       return pd.DataFrame()
def load_bad_hashes():
   try:
       mb = pg_query("SELECT sha256, file_name FROM malwarebazaar")
       lol = pg_query("SELECT sha256, name, standard_path FROM lolbas")
       return mb, lol
   except Exception as e:
       st.warning(f"⚠️ Could not load bad hashes: {e}")
       return pd.DataFrame(), pd.DataFrame()

def enrich_files_with_hits(files_df, scan_df, malware_df):
   files_df["malware_hit"] = files_df["sha256"].isin(malware_df["sha256"])
   files_df["lolbas_hit"] = False
   files_df["yara_hit"] = False
   for _, row in scan_df.iterrows():
       path = row["path"]
       det = str(row["Detection"]).lower()
       if "lolbas" in det:
           files_df.loc[files_df["path"] == path, "lolbas_hit"] = True
       if "yara" in det:
           files_df.loc[files_df["path"] == path, "yara_hit"] = True
   return files_df

def classify_risk(row):
   if row["malware_hit"]:
       return "High"
   elif row["yara_hit"]:
       return "YARA"
   elif row["lolbas_hit"]:
       return "Medium"
   return "Low"

# YARA Rule Template
YARA_TEMPLATE = """
rule Suspicious_{rule_name}
{{
  meta:
      description = "Auto-generated rule for {filename} with high entropy"
      sha256 = "{sha256}"
      created = "{created}"

  strings:
{sections}
  condition:
      uint16(0) == 0x5A4D{size_check}{section_check}
}}
"""

# Function to generate yara rule
def generate_yara_rule(filename, sha256, pe_sections, size):
  from datetime import datetime
  rule_name = filename.lower().replace('.', '_').replace('-', '_').replace(' ', '_')[:32]
  created = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " UTC"

  ignore_sections = {'.rsrc', '.text', '.data', '.reloc', '.bss', '.edata'}
  bad_sections = []
  sections = ""
  section_check = ""

  if pe_sections:
      section_list = [s.strip() for s in pe_sections.split(",") if s.strip()]
      for sec in section_list:
          if sec.lower() not in ignore_sections:
              bad_sections.append(sec)

  if not bad_sections:
      return None

  for i, sec in enumerate(bad_sections):
      sections += f'        $section{i+1} = "{sec}"\n'
  section_check = " and any of ($section*)"

  size_check = ""
  if size and size <= 5 * 1024 * 1024:
      size_check = f" and filesize < {int(size) + 1024}"

  rule = YARA_TEMPLATE.format(
      rule_name=rule_name,
      filename=filename,
      sha256=sha256,
      created=created,
      sections=sections,
      size_check=size_check,
      section_check=section_check
  )
  return rule

# Load and process data
files_df = load_files()
scan_df = load_scan_findings()
malware_df, lolbas_df = load_bad_hashes()
files_df = enrich_files_with_hits(files_df, scan_df, malware_df)
files_df["Risk Level"] = files_df.apply(classify_risk, axis=1)
event_df = load_eventlog_entries()

# UI
st.markdown("### 🕵🏾‍♀️ Retro Hunter - Security Scanner & Threat Audit")
st.sidebar.title("🔍 Filter")
hostnames = sorted(files_df["hostname"].dropna().unique())
selected_hosts = st.sidebar.multiselect("Hostnames", hostnames, default=hostnames)
date_range = st.sidebar.date_input("Date Range", [])

filtered = files_df[files_df["hostname"].isin(selected_hosts)]
scan_filtered = scan_df.copy()
if len(date_range) == 2:
   start, end = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])
   filtered = filtered[(filtered["rp_timestamp"] >= start) & (filtered["rp_timestamp"] <= end)]
   scan_filtered = scan_filtered[(scan_filtered["rp_timestamp"] >= start) & (scan_filtered["rp_timestamp"] <= end)]
   if not event_df.empty:
       event_df["RP Timestamp"] = pd.to_datetime(event_df["RP Timestamp"], errors='coerce')
       event_df = event_df[(event_df["RP Timestamp"] >= start) & (event_df["RP Timestamp"] <= end)]

suspicious = filtered[(filtered["malware_hit"]) | (filtered["lolbas_hit"]) | (filtered["yara_hit"])]

malware_files = suspicious["malware_hit"].sum()
malware_scan = scan_filtered["Detection"].str.lower().str.contains("malware", na=False).sum()
lolbas_scan = scan_filtered["Detection"].str.lower().str.contains("lolbas", na=False).sum()
yara_scan = scan_filtered["Detection"].str.lower().str.contains("yara", na=False).sum()

# KPI Section
st.markdown("---")
col1, col2, col3, col4 = st.columns(4)
col1.metric("🦠 Malware Matches", malware_files + malware_scan)
col2.metric("🛠️ LOLBAS Hits", lolbas_scan)
col3.metric("🔬 YARA Matches", yara_scan)
col4.metric("📂 Total Files", len(filtered))

# Suspicious Table - Those are coming from the store.py script
st.markdown("### 🐞 Suspicious Files")
if not suspicious.empty:
   suspicious_view = suspicious.rename(columns={
       "hostname": "Host", "filename": "Filename", "path": "Path", "sha256": "SHA-256",
       "inserted_at": "Inserted At", "rp_timestamp": "RP Timestamp", "rp_status": "RP Status"
   })
   suspicious_view["VT Link"] = suspicious_view["SHA-256"].apply(
       lambda h: f"https://www.virustotal.com/gui/file/{h}"
   )
   st.dataframe(suspicious_view[
       ["Host", "Filename", "Path", "Risk Level", "RP Timestamp", "RP Status", "Inserted At", "VT Link"]
   ], use_container_width=True)
else:
   st.info("No suspicious files found.")

# Scan findings - From scanner.py
st.markdown("### 🔍 Scan Findings")
if not scan_filtered.empty:
   scan_view = scan_filtered.rename(columns={
       "hostname": "Host", "path": "Path", "sha256": "SHA-256",
       "rp_timestamp": "RP Timestamp", "rp_status": "RP Status", "scanned_at": "Last Scan"
   })
   st.dataframe(scan_view.sort_values("Last Scan", ascending=False)[
       ["Host", "Path", "SHA-256", "Detection", "RP Timestamp", "RP Status", "Last Scan"]
   ], use_container_width=True)
else:
   st.info("No scan findings found.")

st.markdown("### 📊 Deep Analysis")

run_analysis_query("💣 Large Executables > 50MB", """
 SELECT hostname AS Host, filename AS Filename, path AS Path, ROUND(size / 1048576.0, 2) AS Size_MB
 FROM files
 WHERE filename LIKE '%%.exe' AND size > 52428800
""")

run_analysis_query("📁 Suspicious EXEs in AppData", """
 SELECT hostname AS Host, filename AS Filename, path AS Path
 FROM files
 WHERE LOWER(path) LIKE '%%appdata%%' AND filename LIKE '%%.exe'
""")

run_analysis_query("📂 Scripts in Temp/Download Directories", """
 SELECT hostname AS Host, filename AS Filename, path AS Path
 FROM files
 WHERE filetype = 'script' AND (
     LOWER(path) LIKE '%%/tmp/%%' OR LOWER(path) LIKE '%%\\temp\\%%' OR LOWER(path) LIKE '%%\\downloads\\%%'
 )
""")

run_analysis_query("🌀 Multi-use Hashes (Same SHA256, multiple filenames)", """
SELECT sha256 AS "SHA-256",
      MIN(path) AS "Path",
      COUNT(DISTINCT filename) AS "Filename Count",
      STRING_AGG(DISTINCT filename, ', ') AS "Filenames"
FROM files
WHERE LOWER(path) NOT LIKE '%%/windows/%%'
 AND LOWER(path) NOT LIKE '%%/winsxs/%%'
 AND LOWER(path) NOT LIKE '%%/appdata/%%'
 AND LOWER(path) NOT LIKE '%%/recycle.bin/%%'
GROUP BY sha256
HAVING COUNT(DISTINCT filename) > 1
""")

run_analysis_query("⚙️ System Process Names Outside System32", """
 SELECT hostname AS Host, filename AS Filename, path AS Path
 FROM files
 WHERE LOWER(filename) IN (
     'lsass.exe', 'services.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'svchost.exe', 'explorer.exe',
     'conhost.exe', 'taskhostw.exe', 'dwm.exe', 'ctfmon.exe', 'spoolsv.exe', 'searchindexer.exe',
     'wuauclt.exe', 'lsm.exe', 'wininit.exe', 'taskeng.exe', 'dllhost.exe', 'rundll32.exe', 'msiexec.exe',
     'sihost.exe', 'fontdrvhost.exe'
 ) AND NOT (
     LOWER(path) LIKE '%%/windows/system32%%' OR LOWER(path) LIKE '%%/windows/winsxs%%' OR
     LOWER(path) LIKE '%%/windows/servicing/lcu/%%' OR LOWER(path) LIKE '%%/windows%%'
 )
""")

run_analysis_query("🧠 High-Entropy Files in Suspicious Paths", """
SELECT filename AS Filename, path AS Path, sha256 AS "SHA-256",
      ROUND(CAST(entropy AS NUMERIC), 2) AS Entropy, suspicious_structure AS "Suspicious_Path"
FROM files
WHERE entropy > 7.5 AND suspicious_structure = 'yes'
ORDER BY entropy DESC
LIMIT 100
""")

# PE Timestamp: Ensure correct datetime handling
filtered["pe_timestamp"] = pd.to_datetime(filtered["pe_timestamp"], errors='coerce').dt.tz_localize(None)

pe_filtered_df = filtered[
  (filtered["filetype"] == "executable") &
  (filtered["entropy"] >= 7.9) &
  (filtered["pe_timestamp"] >= pd.to_datetime("2024-06-15"))
]

st.markdown("### 🧬 High-Entropy Executables with PE Metadata")
if pe_filtered_df.empty:
  st.info("No high-entropy executables with recent PE timestamp found.")
else:
  pe_filtered_df = pe_filtered_df.sort_values("entropy", ascending=False).head(100)

  pe_filtered_df["VT Link"] = pe_filtered_df["sha256"].apply(
      lambda h: f"https://www.virustotal.com/gui/file/{h}"
  )

  pe_view = pe_filtered_df.rename(columns={
      "hostname": "Host",
      "filename": "Filename",
      "path": "Path",
      "rp_timestamp": "RP Timestamp",
      "magic_type": "Magic Type",
      "pe_timestamp": "PE Timestamp",
      "pe_sections": "PE Sections",
      "entropy": "Entropy",
      "sha256": "SHA-256"
  })

  pe_view["Entropy"] = pe_view["Entropy"].round(2)

  st.dataframe(
      pe_view[
          ["Host", "Filename", "Path", "RP Timestamp", "Entropy",
           "Magic Type", "PE Timestamp", "PE Sections", "SHA-256", "VT Link"]
      ],
      use_container_width=True
  )

st.markdown("### 🛡️ On-demand YARA Rule Generator")
if not pe_filtered_df.empty:
  selected_filename = st.selectbox("Select a file for YARA rule", pe_filtered_df["filename"].unique())
  selected_row = pe_filtered_df[pe_filtered_df["filename"] == selected_filename].iloc[0] if selected_filename else None
  if selected_row is not None:
      if st.button("🚀 Generate YARA Rule for Selected File"):
          with st.spinner("Generating YARA rule..."):
              filename = selected_row["filename"]
              sha256 = selected_row["sha256"]
              pe_sections = selected_row["pe_sections"]
              size = selected_row["size"]
              yara_rule = generate_yara_rule(filename, sha256, pe_sections, size)
              if not yara_rule:
                  st.warning("⚠️ No YARA rule generated — no unusual PE sections found.")
              else:
                  st.success("✅ YARA rule generated successfully.")
                  st.text_area("Generated YARA Rule", yara_rule, height=300)
                  st.download_button(
                      label="💾 Download YARA Rule (.yar)",
                      data=yara_rule,
                      file_name=f"{filename}_rule.yar",
                      mime="text/plain"
                  )
else:
  st.info("No suitable high-entropy PE files found for YARA rule generation.")

# Eventlog
st.markdown("### 📑 Windows Event Log Entries")
if not event_df.empty:
   event_df["Level"] = event_df["Event ID"].apply(classify_event_severity)
   st.dataframe(event_df, use_container_width=True)
else:
   st.info("No relevant event log entries found.")

# Footer
st.markdown("---")
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
st.caption(f"🕵🏾‍♀️ Retro Hunter – powered by Veeam Data Integration API ({now}) - Version 2.0 PostgreSQL")
st.caption("🤖 Some logic and optimizations were assisted using AI tools.")
