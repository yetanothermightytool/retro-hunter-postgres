import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
from sqlalchemy import create_engine, text
from datetime import datetime
from dotenv import load_dotenv
import os
from functools import lru_cache

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

@lru_cache(maxsize=None)
def table_exists(table_name: str, schema: str = "public") -> bool:
    
    try:
        with engine.connect() as conn:
            fq = f"{schema}.{table_name}" if "." not in table_name else table_name
            res = conn.execute(text("SELECT to_regclass(:fqname)"), {"fqname": fq}).scalar()
            return res is not None
    except Exception:
        return False

def empty_df(columns: list[str]) -> pd.DataFrame:
    
    return pd.DataFrame({c: pd.Series(dtype="object") for c in columns})

def ensure_cols(df: pd.DataFrame, required: list[str]) -> pd.DataFrame:
    
    for c in required:
        if c not in df.columns:
            df[c] = pd.Series(dtype="object")
    return df

def safe_pg_query(sql: str,
                  depends_on: list[str] | None = None,
                  expected_cols: list[str] | None = None) -> pd.DataFrame:
    if expected_cols is None:
        expected_cols = []
    if depends_on:
        missing = [t for t in depends_on if not table_exists(t)]
        if missing:
            return empty_df(expected_cols)

    try:
        df = pd.read_sql_query(sql, engine)
    except Exception:
        df = empty_df(expected_cols)
    if expected_cols:
        df = ensure_cols(df, expected_cols)
    return df

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
       expected = ["hostname","rp_timestamp","rp_status","inserted_at","filename",
                   "path","sha256","filetype","entropy","size","magic_type",
                   "pe_timestamp","pe_sections","suspicious_structure"]
       df = safe_pg_query("SELECT * FROM files", depends_on=["files"], expected_cols=expected)
       # No warning here anymore; just return df (may be empty if missing)
       if df.empty:
           return df
       # Normalize as in your original approach
       if "hostname" in df:
           df["hostname"] = df["hostname"].astype(str).str.strip().str.lower()
       if "rp_timestamp" in df:
           df["rp_timestamp"] = pd.to_datetime(df["rp_timestamp"], errors="coerce").dt.tz_localize(None)
       if "rp_status" in df:
           df["rp_status"] = df["rp_status"].fillna("unknown")
       if "inserted_at" in df:
           df["inserted_at"] = pd.to_datetime(df.get("inserted_at", None), errors="coerce").dt.tz_localize(None)
       return df
   except Exception as e:
       st.warning(f"⚠️ Could not load files: {e}")
       return pd.DataFrame()

def load_scan_findings():
   try:
       cols = ["path","sha256","Detection","hostname","rp_timestamp","rp_status","scanned_at"]
       df = safe_pg_query("""
           SELECT path, sha256, detection AS "Detection", hostname, rp_timestamp, rp_status, scanned_at
           FROM scan_findings
       """, depends_on=["scan_findings"], expected_cols=cols)
       if df.empty:
           return df
       if "rp_timestamp" in df:
           df["rp_timestamp"] = pd.to_datetime(df["rp_timestamp"], errors="coerce").dt.tz_localize(None)
       if "scanned_at" in df:
           df["scanned_at"] = pd.to_datetime(df["scanned_at"], errors="coerce").dt.tz_localize(None)
       if "rp_status" in df:
           df["rp_status"] = df["rp_status"].fillna("unknown")
       return df
   except Exception as e:
       st.warning(f"⚠️ Could not load scan findings: {e}")
       return pd.DataFrame()

def load_eventlog_entries():
   try:
       cols = ["Host","RP Timestamp","Event ID","Level","Event Time","Source","Message"]
       df = safe_pg_query("""
           SELECT hostname AS Host, rp_timestamp AS "RP Timestamp", event_id AS "Event ID",
                  level AS Level, timestamp AS "Event Time", source AS Source, message AS Message
           FROM win_events
           WHERE event_id IN (
               4104, 4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124, 1102, 550, 800
           )
           ORDER BY "Event Time" DESC
           LIMIT 100
       """, depends_on=["win_events"], expected_cols=cols)
       if not df.empty and "RP Timestamp" in df:
           df["RP Timestamp"] = pd.to_datetime(df["RP Timestamp"], errors="coerce").dt.tz_localize(None)
       return df
   except Exception as e:
       st.warning(f"⚠️ Could not load event log entries: {e}")
       return pd.DataFrame()

def load_bad_hashes():
   try:
       mb_cols = ["sha256", "file_name"]
       lol_cols = ["sha256", "name", "standard_path"]
       mb = safe_pg_query("SELECT sha256, file_name FROM malwarebazaar",
                          depends_on=["malwarebazaar"], expected_cols=mb_cols)
       lol = safe_pg_query("SELECT sha256, name, standard_path FROM lolbas",
                           depends_on=["lolbas"], expected_cols=lol_cols)
       return mb, lol
   except Exception as e:
       st.warning(f"⚠️ Could not load bad hashes: {e}")
       return pd.DataFrame(), pd.DataFrame()

def enrich_files_with_hits(files_df, scan_df, malware_df):
   if files_df is None or files_df.empty:
       return files_df
   files_df = files_df.copy()
   if "sha256" in files_df.columns and not malware_df.empty and "sha256" in malware_df.columns:
       files_df["malware_hit"] = files_df["sha256"].isin(malware_df["sha256"])
   else:
       files_df["malware_hit"] = False
   files_df["lolbas_hit"] = files_df.get("lolbas_hit", False)
   files_df["yara_hit"] = files_df.get("yara_hit", False)
   if scan_df is not None and not scan_df.empty and "path" in scan_df and "Detection" in scan_df:
       for _, row in scan_df.iterrows():
           path = row.get("path")
           det = str(row.get("Detection", "")).lower()
           if path is None:
               continue
           if "lolbas" in det and "path" in files_df:
               files_df.loc[files_df["path"] == path, "lolbas_hit"] = True
           if "yara" in det and "path" in files_df:
               files_df.loc[files_df["path"] == path, "yara_hit"] = True
   return files_df

def classify_risk(row):
   if bool(row.get("malware_hit")):
       return "High"
   elif bool(row.get("yara_hit")):
       return "YARA"
   elif bool(row.get("lolbas_hit")):
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
  try:
      if size and float(size) <= 5 * 1024 * 1024:
          size_check = f" and filesize < {int(float(size)) + 1024}"
  except Exception:
      pass

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

# Enrich files safely
if files_df is not None and not files_df.empty:
    files_df = enrich_files_with_hits(files_df, scan_df, malware_df)
    try:
        files_df["Risk Level"] = files_df.apply(classify_risk, axis=1)
    except Exception as e:
        st.warning(f"⚠️ Could not compute risk levels: {e}")

event_df = load_eventlog_entries()

# UI with Tabs
st.markdown("### 🕵🏾‍♀️ Retro Hunter - Security Scanner & Threat Audit")
st.sidebar.title("🔍 Filter")

# Sidebar filters 
if files_df is not None and "hostname" in files_df.columns:
    hostnames = sorted(files_df["hostname"].dropna().unique())
else:
    hostnames = []
selected_hosts = st.sidebar.multiselect("Hostnames", hostnames, default=hostnames)
date_range = st.sidebar.date_input("Date Range", [])

filtered = files_df.copy() if files_df is not None else pd.DataFrame()
if not filtered.empty and "hostname" in filtered.columns and selected_hosts:
    filtered = filtered[filtered["hostname"].isin(selected_hosts)]

scan_filtered = scan_df.copy() if scan_df is not None else pd.DataFrame()
if len(date_range) == 2:
    start, end = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])

    if not filtered.empty and "rp_timestamp" in filtered.columns:
        filtered["rp_timestamp"] = pd.to_datetime(filtered["rp_timestamp"], errors="coerce").dt.tz_localize(None)
        filtered = filtered[(filtered["rp_timestamp"] >= start) & (filtered["rp_timestamp"] <= end)]
    if not scan_filtered.empty and "rp_timestamp" in scan_filtered.columns:
        scan_filtered["rp_timestamp"] = pd.to_datetime(scan_filtered["rp_timestamp"], errors="coerce").dt.tz_localize(None)
        scan_filtered = scan_filtered[(scan_filtered["rp_timestamp"] >= start) & (scan_filtered["rp_timestamp"] <= end)]
    if event_df is not None and not event_df.empty and "RP Timestamp" in event_df.columns:
        event_df["RP Timestamp"] = pd.to_datetime(event_df["RP Timestamp"], errors="coerce").dt.tz_localize(None)
        event_df = event_df[(event_df["RP Timestamp"] >= start) & (event_df["RP Timestamp"] <= end)]

# Suspicious subset
if filtered is not None and not filtered.empty:
    suspicious = filtered[
        filtered.get("malware_hit", pd.Series(False, index=filtered.index)) |
        filtered.get("lolbas_hit", pd.Series(False, index=filtered.index)) |
        filtered.get("yara_hit", pd.Series(False, index=filtered.index))
    ]
else:
    suspicious = pd.DataFrame()

# KPIs
malware_files = int(suspicious.get("malware_hit", pd.Series(dtype=bool)).sum()) if not suspicious.empty else 0
malware_scan = int(
    scan_filtered.get("Detection", pd.Series(dtype=object)).astype(str).str.lower().str.contains("malware", na=False).sum()
) if not scan_filtered.empty else 0
lolbas_scan = int(
    scan_filtered.get("Detection", pd.Series(dtype=object)).astype(str).str.lower().str.contains("lolbas", na=False).sum()
) if not scan_filtered.empty else 0
yara_scan = int(
    scan_filtered.get("Detection", pd.Series(dtype=object)).astype(str).str.lower().str.contains("yara", na=False).sum()
) if not scan_filtered.empty else 0

# Helper for downloads (CSV)
def df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    """Return DataFrame as CSV bytes for download buttons."""
    return df.to_csv(index=False).encode("utf-8")

# Tabs
tab_overview, tab_scans, tab_analysis, tab_events = st.tabs(["Overview", "Scans", "Deep Analysis", "Events"])

with tab_overview:
    # KPI Section
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🦠 Malware Matches", malware_files + malware_scan)
    col2.metric("🛠️ LOLBAS Hits", lolbas_scan)
    col3.metric("🔬 YARA Matches", yara_scan)
    col4.metric("📂 Total Files", len(filtered) if filtered is not None else 0)

    # Malware Hash Matches 
    st.markdown("### 🐞 Malware Hash Matches")
    comparison_count = len(malware_df) if malware_df is not None else 0
    st.markdown(
       f"<div style='font-size: 0.85em; color: gray;'>Compared against {comparison_count:,} known malware hashes</div>",
       unsafe_allow_html=True
    )
    if suspicious is not None and not suspicious.empty:
        suspicious_view = suspicious.rename(columns={
            "hostname": "Host", "filename": "Filename", "path": "Path", "sha256": "SHA-256",
            "inserted_at": "Inserted At", "rp_timestamp": "RP Timestamp", "rp_status": "RP Status"
        }).copy()
        if "SHA-256" in suspicious_view.columns:
            suspicious_view["VT Link"] = suspicious_view["SHA-256"].apply(
                lambda h: f"https://www.virustotal.com/gui/file/{h}"
            )
        display_cols = [c for c in ["Host", "Filename", "Path", "Risk Level", "RP Timestamp", "RP Status", "Inserted At", "VT Link"] if c in suspicious_view.columns]
        st.dataframe(
            suspicious_view[display_cols],
            use_container_width=True,
            column_config={
                "VT Link": st.column_config.LinkColumn(display_text="Open in VirusTotal"),
                "Entropy": st.column_config.NumberColumn(format="%.2f"),
                "RP Timestamp": st.column_config.DatetimeColumn(),
                "Inserted At": st.column_config.DatetimeColumn(),
            }
        )
        st.download_button(
            "⬇️ Download suspicious.csv",
            df_to_csv_bytes(suspicious_view[display_cols]),
            file_name="suspicious.csv",
            mime="text/csv"
        )
    else:
        st.info("No suspicious files found.")

    # Mini charts (ADD-ON)
    if 'hostname' in filtered.columns and not filtered.empty:
        st.subheader("Files per Host")
        st.bar_chart(filtered['hostname'].value_counts())
    if 'rp_timestamp' in filtered.columns and not filtered.empty:
        st.subheader("Files over Time")
        _tmp = filtered[['rp_timestamp']].dropna().copy()
        _tmp['date'] = pd.to_datetime(_tmp['rp_timestamp']).dt.tz_localize(None).dt.date
        st.line_chart(_tmp.groupby('date').size())

with tab_scans:
    st.markdown("### 🔍 Scan Findings")
    if scan_filtered is not None and not scan_filtered.empty:
        scan_view = scan_filtered.rename(columns={
            "hostname": "Host", "path": "Path", "sha256": "SHA-256",
            "rp_timestamp": "RP Timestamp", "rp_status": "RP Status", "scanned_at": "Last Scan"
        }).copy()
        sort_col = "Last Scan" if "Last Scan" in scan_view.columns else None
        if sort_col:
            scan_view = scan_view.sort_values(sort_col, ascending=False)
        display_cols = [c for c in ["Host", "Path", "SHA-256", "Detection", "RP Timestamp", "RP Status", "Last Scan"] if c in scan_view.columns]
        st.dataframe(scan_view[display_cols], use_container_width=True)
        st.download_button(
            "⬇️ Download scans.csv",
            df_to_csv_bytes(scan_view[display_cols]),
            file_name="scans.csv",
            mime="text/csv"
        )
    else:
        st.info("No scan findings found.")

with tab_analysis:
    st.markdown("### 📊 Deep Analysis")

    # Analysis queries 
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

    run_analysis_query("🧬 Suspicious IFEO Debuggers (Registry Scan)", """
    SELECT hostname AS Host, key_path AS "Key Path", value_name as "Value Name", value_data AS "Value Data", rp_timestamp AS "RP Timestamp"
    FROM registry_scan
    WHERE key_path LIKE '%%Image File Execution Options%%'
    AND value_name = 'Debugger'
    AND (
        value_data LIKE '%%cmd.exe%%' OR
        value_data LIKE '%%powershell.exe%%' OR
        value_data LIKE '%%wscript.exe%%' OR
        value_data LIKE '%%cscript.exe%%' OR
        value_data LIKE '%%\\Users\\%%' OR
        value_data LIKE '%%\\Temp\\%%' OR
        value_data LIKE '%%\\AppData\\%%' OR
        value_data LIKE '%%rat.exe%%' OR
        value_data LIKE '%%payload%%' OR
        value_data LIKE '%%\\Tasks\\%%' OR
        value_data LIKE '%%\\explorer.exe%%' OR
        value_data LIKE '%%\\svchost.exe%%'
        )
    LIMIT 100
    """)

    # PE section
    if filtered is None or filtered.empty:
        filtered = pd.DataFrame()

    if "pe_timestamp" in filtered.columns:
        filtered["pe_timestamp"] = pd.to_datetime(filtered["pe_timestamp"], errors='coerce').dt.tz_localize(None)
    else:
        filtered["pe_timestamp"] = pd.Series(pd.NaT, index=filtered.index, dtype="datetime64[ns]")

    filetype_mask = filtered["filetype"].eq("executable") if "filetype" in filtered.columns else pd.Series(False, index=filtered.index)
    entropy_mask = pd.to_numeric(filtered["entropy"], errors="coerce") >= 7.9 if "entropy" in filtered.columns else pd.Series(False, index=filtered.index)
    pet_mask = filtered["pe_timestamp"] >= pd.to_datetime("2024-06-15")

    pe_filtered_df = filtered[filetype_mask & entropy_mask & pet_mask]

    st.markdown("### 🧬 High-Entropy Executables with PE Metadata")
    if pe_filtered_df.empty:
      st.info("No high-entropy executables with recent PE timestamp found.")
    else:
      try:
          pe_filtered_df = pe_filtered_df.sort_values("entropy", ascending=False).head(100)
      except Exception:
          pass

      if "sha256" in pe_filtered_df.columns:
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

      if "Entropy" in pe_view.columns:
          pe_view["Entropy"] = pd.to_numeric(pe_view["Entropy"], errors="coerce").round(2)

      display_cols = [c for c in
          ["Host", "Filename", "Path", "RP Timestamp", "Entropy",
           "Magic Type", "PE Timestamp", "PE Sections", "SHA-256", "VT Link"]
          if c in pe_view.columns
      ]

      st.dataframe(pe_view[display_cols], use_container_width=True)
      st.download_button(
          "⬇️ Download high_entropy_pe.csv",
          df_to_csv_bytes(pe_view[display_cols]),
          file_name="high_entropy_pe.csv",
          mime="text/csv"
      )

    st.markdown("### 🛡️ On-demand YARA Rule Generator")
    if not pe_filtered_df.empty and "filename" in pe_filtered_df.columns:
      selected_filename = st.selectbox("Select a file for YARA rule", pe_filtered_df["filename"].dropna().unique())
      selected_row = pe_filtered_df[pe_filtered_df["filename"] == selected_filename].iloc[0] if selected_filename is not None and len(pe_filtered_df[pe_filtered_df["filename"] == selected_filename]) > 0 else None
      if selected_row is not None:
          if st.button("🚀 Generate YARA Rule for Selected File"):
              with st.spinner("Generating YARA rule..."):
                  filename = selected_row.get("filename")
                  sha256 = selected_row.get("sha256")
                  pe_sections = selected_row.get("pe_sections")
                  size = selected_row.get("size")
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

with tab_events:
    st.markdown("### 📑 Windows Event Log Entries")
    if event_df is not None and not event_df.empty:
       if "Event ID" in event_df.columns:
           event_df["Level"] = event_df["Event ID"].apply(classify_event_severity)
       st.dataframe(event_df, use_container_width=True)
       st.download_button(
           "⬇️ Download events.csv",
           df_to_csv_bytes(event_df),
           file_name="events.csv",
           mime="text/csv"
       )
    else:
       st.info("No relevant event log entries found.")

# Footer
st.markdown("---")
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
st.caption(f"🕵🏾‍♀️ Retro Hunter – powered by Veeam Data Integration API ({now}) - Version 2.3 PostgreSQL")
st.caption("🤖 Some logic and optimizations were assisted using AI tools.")
