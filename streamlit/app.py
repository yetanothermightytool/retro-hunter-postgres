# Retro Hunter – Security Analysis Dashboard
import streamlit as st
import pandas as pd
import psycopg2
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool
from datetime import datetime
from dotenv import load_dotenv
import os
from functools import lru_cache
from cachetools import TTLCache, cached   # TTL cache for table existence checks

# Environment & DB connection (connection pool)
load_dotenv()

PG_HOST = os.getenv("POSTGRES_HOST", "db")
PG_PORT = os.getenv("POSTGRES_PORT", "5432")
PG_DB   = os.getenv("POSTGRES_DB", "retro-hunter")
PG_USER = os.getenv("POSTGRES_USER")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD")

# Engine with a small pool – adjust via env vars if needed
POOL_SIZE    = int(os.getenv("DB_POOL_SIZE", 5))
MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", 10))
POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", 30))

engine = create_engine(
    f"postgresql+psycopg2://{PG_USER}:{PG_PASSWORD}@{PG_HOST}:{PG_PORT}/{PG_DB}",
    poolclass=QueuePool,
    pool_size=POOL_SIZE,
    max_overflow=MAX_OVERFLOW,
    pool_timeout=POOL_TIMEOUT,
    future=True,
)

# Helper: read_sql – always uses a connection from the pool
def read_sql(query: str, params: dict | None = None) -> pd.DataFrame:
    """Execute a query and return a DataFrame."""
    with engine.connect() as conn:
        return pd.read_sql_query(text(query), conn, params=params)

# TTL cache for table existence (5 minute freshness)
_table_exists_cache = TTLCache(maxsize=128, ttl=300)   # 5 minutes

@cached(_table_exists_cache)
def table_exists(table_name: str, schema: str = "public") -> bool:
    """Check whether a table/view exists – result cached for 5-min."""
    try:
        with engine.connect() as conn:
            fq = f"{schema}.{table_name}" if "." not in table_name else table_name
            res = conn.execute(text("SELECT to_regclass(:fqname)"),
                               {"fqname": fq}).scalar()
            return res is not None
    except Exception:
        return False

# Small utility helpers
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
    """Run a query only if dependent tables exist; otherwise return empty DF."""
    if expected_cols is None:
        expected_cols = []
    if depends_on:
        missing = [t for t in depends_on if not table_exists(t)]
        if missing:
            return empty_df(expected_cols)

    try:
        df = read_sql(sql)
    except Exception:
        df = empty_df(expected_cols)

    if expected_cols:
        df = ensure_cols(df, expected_cols)
    return df

def get_pg_conn():
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASSWORD,
    )

def classify_event_severity(event_id: int) -> str:
    high_ids = {
        4104, 4618, 4649, 4719, 4765, 4766,
        4794, 4897, 4964, 5124,
    }
    medium_high_ids = {800, 1102}
    if event_id in high_ids:
        return "High"
    if event_id in medium_high_ids:
        return "Medium to High"
    return "Low"

def pg_query(query: str) -> pd.DataFrame:
    try:
        return read_sql(query)
    except Exception as e:
        st.warning(f"❌ Query failed: {e}")
        return pd.DataFrame()

def run_analysis_query(title: str, query: str):
    try:
        df = read_sql(query)
        if df.empty:
            st.info(f"No entries found for: {title}")
        else:
            st.markdown(f"#### {title}")
            st.dataframe(df, use_container_width=True)
    except Exception as e:
        st.warning(f"❌ Query failed: {e}")

# Data loading functions
def load_files() -> pd.DataFrame:
    expected = [
        "hostname", "rp_timestamp", "rp_status", "inserted_at", "filename",
        "path", "sha256", "filetype", "entropy", "size", "magic_type",
        "pe_timestamp", "pe_sections", "suspicious_structure",
    ]
    df = safe_pg_query(
        "SELECT * FROM files",
        depends_on=["files"],
        expected_cols=expected,
    )

    if df.empty:
        return df

    if "hostname" in df:
        df["hostname"] = df["hostname"].astype(str).str.strip().str.lower()
    if "rp_timestamp" in df:
        df["rp_timestamp"] = pd.to_datetime(df["rp_timestamp"], errors="coerce").dt.tz_localize(None)
    if "rp_status" in df:
        df["rp_status"] = df["rp_status"].fillna("unknown")
    if "inserted_at" in df:
        df["inserted_at"] = pd.to_datetime(df.get("inserted_at"), errors="coerce").dt.tz_localize(None)

    return df

def load_scan_findings() -> pd.DataFrame:
    cols = [
        "path", "sha256", "Detection", "hostname",
        "rp_timestamp", "rp_status", "scanned_at",
    ]
    df = safe_pg_query(
        """
        SELECT path, sha256, detection AS "Detection", hostname,
               rp_timestamp, rp_status, scanned_at
        FROM scan_findings
        """,
        depends_on=["scan_findings"],
        expected_cols=cols,
    )

    if df.empty:
        return df

    if "rp_timestamp" in df:
        df["rp_timestamp"] = pd.to_datetime(df["rp_timestamp"], errors="coerce").dt.tz_localize(None)
    if "scanned_at" in df:
        df["scanned_at"] = pd.to_datetime(df["scanned_at"], errors="coerce").dt.tz_localize(None)
    if "rp_status" in df:
        df["rp_status"] = df["rp_status"].fillna("unknown")
    return df

def load_nas_scan_findings() -> pd.DataFrame:
   cols = [
       "share_name",
       "file_path",
       "scan_engine",
       "detection",
       "restore_point_time",
       "scanned_at",
   ]
   df = safe_pg_query(
       """
       SELECT
           share_name,
           file_path,
           scan_engine,
           detection,
           restore_point_time,
           scanned_at
       FROM nas_scan_findings
       """,
       depends_on=["nas_scan_findings"],
       expected_cols=cols,
   )

   if df.empty:
       return df

   if "restore_point_time" in df:
       df["restore_point_time"] = pd.to_datetime(
           df["restore_point_time"], errors="coerce"
       ).dt.tz_localize(None)
   if "scanned_at" in df:
       df["scanned_at"] = pd.to_datetime(
           df["scanned_at"], errors="coerce"
       ).dt.tz_localize(None)

   return df

def load_eventlog_entries() -> pd.DataFrame:
    cols = [
        "Host", "RP Timestamp", "Event ID", "Level",
        "Event Time", "Source", "Message",
    ]
    df = safe_pg_query(
        """
        SELECT hostname AS Host,
               rp_timestamp AS "RP Timestamp",
               event_id AS "Event ID",
               level AS Level,
               timestamp AS "Event Time",
               source AS Source,
               message AS Message
        FROM win_events
        WHERE event_id IN (
            4104, 4618, 4649, 4719, 4765, 4766,
            4794, 4897, 4964, 5124, 1102, 550, 800
        )
        ORDER BY "Event Time" DESC
        LIMIT 100
        """,
        depends_on=["win_events"],
        expected_cols=cols,
    )

    if not df.empty and "RP Timestamp" in df:
        df["RP Timestamp"] = pd.to_datetime(df["RP Timestamp"], errors="coerce").dt.tz_localize(None)
    return df

def load_bad_hashes():
    mb_cols = ["sha256", "file_name"]
    lol_cols = ["sha256", "name", "standard_path"]

    mb = safe_pg_query(
        "SELECT sha256, file_name FROM malwarebazaar",
        depends_on=["malwarebazaar"],
        expected_cols=mb_cols,
    )
    lol = safe_pg_query(
        "SELECT sha256, name, standard_path FROM lolbas",
        depends_on=["lolbas"],
        expected_cols=lol_cols,
    )
    return mb, lol


def enrich_files_with_hits(files_df: pd.DataFrame,
                           scan_df: pd.DataFrame,
                           malware_df: pd.DataFrame) -> pd.DataFrame:
    """Add boolean flags for malware / lolbas / yara hits."""
    if files_df is None or files_df.empty:
        return files_df

    files_df = files_df.copy()

    # Malware flag
    if "sha256" in files_df.columns and not malware_df.empty and "sha256" in malware_df.columns:
        files_df["malware_hit"] = files_df["sha256"].isin(malware_df["sha256"])
    else:
        files_df["malware_hit"] = False

    # Initialise optional flags
    files_df["lolbas_hit"] = files_df.get("lolbas_hit", False)
    files_df["yara_hit"]   = files_df.get("yara_hit",   False)

    # Scan findings → set lolbas / yara flags
    if scan_df is not None and not scan_df.empty and "path" in scan_df and "Detection" in scan_df:
        for _, row in scan_df.iterrows():
            path = row.get("path")
            det  = str(row.get("Detection", "")).lower()
            if not path:
                continue
            if "lolbas" in det and "path" in files_df:
                files_df.loc[files_df["path"] == path, "lolbas_hit"] = True
            if "yara" in det and "path" in files_df:
                files_df.loc[files_df["path"] == path, "yara_hit"] = True

    return files_df

def classify_risk(row) -> str:
    if bool(row.get("malware_hit")):
        return "High"
    if bool(row.get("yara_hit")):
        return "YARA"
    if bool(row.get("lolbas_hit")):
        return "Medium"
    return "Low"
# YARA rule template
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

def generate_yara_rule(filename, sha256, pe_sections, size):
    from datetime import datetime
    rule_name = filename.lower().replace('.', '_').replace('-', '_').replace(' ', '_')[:32]
    created = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " UTC"
    ignore_sections = {'.rsrc', '.text', '.data', '.reloc', '.bss', '.edata'}
    bad_sections = []

    sections = ""
    section_check = ""

    if pe_sections:
        for sec in [s.strip() for s in pe_sections.split(",") if s.strip()]:
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

    return YARA_TEMPLATE.format(
        rule_name=rule_name,
        filename=filename,
        sha256=sha256,
        created=created,
        sections=sections,
        size_check=size_check,
        section_check=section_check,
    )

# UI layout
st.set_page_config(page_title="Retro Hunter - Security Dashboard", layout="wide")
st.title("🕵🏾‍♀️ Retro Hunter – Security Scanner & Threat Audit")

# -------------------- Load data --------------------
files_df = load_files()
scan_df = load_scan_findings()
nas_scan_df = load_nas_scan_findings()
malware_df, lolbas_df = load_bad_hashes()

if files_df is not None and not files_df.empty:
    files_df = enrich_files_with_hits(files_df, scan_df, malware_df)
    try:
        files_df["Risk Level"] = files_df.apply(classify_risk, axis=1)
    except Exception as e:
        st.warning(f"⚠️ Could not compute risk levels: {e}")

event_df = load_eventlog_entries()

# -------------------- Sidebar filters --------------------
st.sidebar.title("🔍 Filters")

# Host filter
if files_df is not None and "hostname" in files_df.columns:
    hostnames = sorted(files_df["hostname"].dropna().unique())
else:
    hostnames = []
selected_hosts = st.sidebar.multiselect("Hostnames", hostnames, default=hostnames)

# Date range filter
date_range = st.sidebar.date_input("Date Range", [])

# Apply filters
filtered = files_df.copy() if files_df is not None else pd.DataFrame()
if not filtered.empty and selected_hosts:
    filtered = filtered[filtered["hostname"].isin(selected_hosts)]

scan_filtered = scan_df.copy() if scan_df is not None else pd.DataFrame()
nas_scan_filtered = nas_scan_df.copy() if nas_scan_df is not None else pd.DataFrame()

if len(date_range) == 2:
    start, end = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])

    if not filtered.empty and "rp_timestamp" in filtered.columns:
        filtered["rp_timestamp"] = pd.to_datetime(filtered["rp_timestamp"],
                                                  errors="coerce").dt.tz_localize(None)
        filtered = filtered[(filtered["rp_timestamp"] >= start) &
                            (filtered["rp_timestamp"] <= end)]

    if not scan_filtered.empty and "rp_timestamp" in scan_filtered.columns:
        scan_filtered["rp_timestamp"] = pd.to_datetime(scan_filtered["rp_timestamp"],
                                                      errors="coerce").dt.tz_localize(None)
        scan_filtered = scan_filtered[(scan_filtered["rp_timestamp"] >= start) &
                                      (scan_filtered["rp_timestamp"] <= end)]
    if not nas_scan_filtered.empty and "restore_point_time" in nas_scan_filtered.columns:
        nas_scan_filtered["restore_point_time"] = pd.to_datetime(
            nas_scan_filtered["restore_point_time"],
            errors="coerce"
        ).dt.tz_localize(None)
        nas_scan_filtered = nas_scan_filtered[
            (nas_scan_filtered["restore_point_time"] >= start) &
            (nas_scan_filtered["restore_point_time"] <= end)
        ]

    if event_df is not None and not event_df.empty and "RP Timestamp" in event_df.columns:
        event_df["RP Timestamp"] = pd.to_datetime(event_df["RP Timestamp"],
                                                 errors="coerce").dt.tz_localize(None)
        event_df = event_df[(event_df["RP Timestamp"] >= start) &
                            (event_df["RP Timestamp"] <= end)]
# Suspicious subset
if not filtered.empty:
    suspicious = filtered[
        filtered.get("malware_hit", pd.Series(False, index=filtered.index)) |
        filtered.get("lolbas_hit",   pd.Series(False, index=filtered.index)) |
        filtered.get("yara_hit",    pd.Series(False, index=filtered.index))
    ]
else:
    suspicious = pd.DataFrame()

# Helper for CSV download
def df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")

# -------------------- Tabs --------------------
tab_overview, tab_scans, tab_analysis, tab_events = st.tabs(
    ["Overview", "Scans", "Deep Analysis", "Events"]
)

# ==================== Overview Tab ====================
with tab_overview:
    st.subheader("📊 KPIs")
    col1, col2, col3, col4 = st.columns(4)

    malware_files = int(suspicious.get("malware_hit",
                                      pd.Series(dtype=bool)).sum()) if not suspicious.empty else 0
    malware_scan = int(
        scan_filtered.get("Detection", pd.Series(dtype=object))
        .astype(str).str.lower().str.contains("malware", na=False).sum()
    ) if not scan_filtered.empty else 0
    lolbas_scan = int(
        scan_filtered.get("Detection", pd.Series(dtype=object))
        .astype(str).str.lower().str.contains("lolbas", na=False).sum()
    ) if not scan_filtered.empty else 0
    yara_scan = int(
        scan_filtered.get("Detection", pd.Series(dtype=object))
        .astype(str).str.lower().str.contains("yara", na=False).sum()
    ) if not scan_filtered.empty else 0

    col1.metric("🦠 Malware Matches", malware_files + malware_scan)
    col2.metric("🛠️ LOLBAS Hits", lolbas_scan)
    col3.metric("🔬 YARA Matches", yara_scan)
    col4.metric("📂 Total Files", len(filtered) if filtered is not None else 0)

    st.markdown("### 🐞 Malware Hash Matches")
    comparison_cnt = len(malware_df) if malware_df is not None else 0
    st.markdown(
        f"<div style='font-size:0.85em;color:gray;'>Compared against "
        f"{comparison_cnt:,} known malware hashes</div>",
        unsafe_allow_html=True,
    )

    if not suspicious.empty:
        view = suspicious.rename(columns={
            "hostname": "Host",
            "filename": "Filename",
            "path": "Path",
            "sha256": "SHA-256",
            "rp_timestamp": "RP Timestamp",
            "rp_status": "RP Status",
            "inserted_at": "Inserted At",
        })
        view["VT Link"] = view["SHA-256"].apply(
            lambda h: f"https://www.virustotal.com/gui/file/{h}"
        )
        display_cols = [
            c for c in ["Host", "Filename", "Path", "Risk Level",
                        "RP Timestamp", "RP Status", "Inserted At",
                        "VT Link"] if c in view.columns
        ]
        st.dataframe(
            view[display_cols],
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
           df_to_csv_bytes(view[display_cols]),
           file_name="suspicious.csv",
           mime="text/csv"
       )
    else:
        st.info("No suspicious files found.")

# ==================== Scans Tab ====================
with tab_scans:
   st.markdown("### 🔍 Scan Findings")
   if not scan_filtered.empty:
       scan_view = scan_filtered.rename(columns={
           "hostname": "Host",
           "path": "Path",
           "sha256": "SHA-256",
           "rp_timestamp": "RP Timestamp",
           "rp_status": "RP Status",
           "scanned_at": "Last Scan",
       })
       sort_col = "Last Scan" if "Last Scan" in scan_view.columns else None
       if sort_col:
           scan_view = scan_view.sort_values(sort_col, ascending=False)

       display_cols = [
           c for c in ["Host", "Path", "SHA-256", "Detection",
                       "RP Timestamp", "RP Status", "Last Scan"]
           if c in scan_view.columns
       ]
       st.dataframe(scan_view[display_cols], use_container_width=True)
       st.download_button(
           "⬇️ Download scans.csv",
           df_to_csv_bytes(scan_view[display_cols]),
           file_name="scans.csv",
           mime="text/csv"
       )
   else:
       st.info("No scan findings found.")

   st.markdown("### 📦 Unstructured Data Scan Findings")
   if not nas_scan_filtered.empty:
       nas_view = nas_scan_filtered.rename(columns={
           "share_name": "Share Name",
           "file_path": "File Path",
           "scan_engine": "Scan Engine",
           "detection": "Detection",
           "restore_point_time": "RP Timestamp",
           "scanned_at": "Last Scan",
       })

       sort_col = "Last Scan" if "Last Scan" in nas_view.columns else None
       if sort_col:
           nas_view = nas_view.sort_values(sort_col, ascending=False)

       display_cols = [
           c for c in [
               "Share Name",
               "File Path",
               "Scan Engine",
               "Detection",
               "RP Timestamp",
               "Last Scan",
           ]
           if c in nas_view.columns
       ]

       st.dataframe(nas_view[display_cols], use_container_width=True)
       st.download_button(
           "⬇️ Download nas_scans.csv",
           df_to_csv_bytes(nas_view[display_cols]),
           file_name="nas_scans.csv",
           mime="text/csv",
       )
   else:
       st.info("No unstructured data scan findings found.")

# ==================== Deep-Analysis Tab ====================
with tab_analysis:
   st.markdown("### 📊 Deep Analysis Queries")

   # ----------------------------------------------------------
   # 1️⃣ Large executables >-50-MB
   # ----------------------------------------------------------
   run_analysis_query(
       "💣 Large Executables >-50-MB",
       """
       SELECT hostname AS Host,
              filename AS Filename,
              path AS Path,
              ROUND(size / 1048576.0, 2) AS Size_MB
       FROM files
       WHERE filename LIKE '%%.exe' AND size > 52428800
       """
   )

   # ----------------------------------------------------------
   # 2️⃣ Suspicious EXEs in AppData
   # ----------------------------------------------------------
   run_analysis_query(
       "📁 Suspicious EXEs in AppData",
       """
       SELECT hostname AS Host,
              filename AS Filename,
              path AS Path
       FROM files
       WHERE LOWER(path) LIKE '%%appdata%%' AND filename LIKE '%%.exe'
       """
   )

   # ----------------------------------------------------------
   # 3️⃣ Scripts in temporary / download folders
   # ----------------------------------------------------------
   run_analysis_query(
       "📂 Scripts in Temp/Download Directories",
       """
       SELECT hostname AS Host,
              filename AS Filename,
              path AS Path
       FROM files
       WHERE filetype = 'script' AND (
           LOWER(path) LIKE '%%/tmp/%%' OR
           LOWER(path) LIKE '%%\\\\temp\\\\%%' OR
           LOWER(path) LIKE '%%\\\\downloads\\\\%%'
       )
       """
   )

   # ----------------------------------------------------------
   # 4️⃣ Multi-use hashes (same SHA-256, multiple filenames)
   # ----------------------------------------------------------
   run_analysis_query(
       "🌀 Multi-use Hashes (Same SHA-256, multiple filenames)",
       """
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
       """
   )

   # ----------------------------------------------------------
   # 5️⃣ System processes outside System32
   # ----------------------------------------------------------
   run_analysis_query(
       "⚙️ System Process Names Outside System32",
       """
       SELECT hostname AS Host,
              filename AS Filename,
              path AS Path
       FROM files
       WHERE LOWER(filename) IN (
           'lsass.exe','services.exe','winlogon.exe','csrss.exe','smss.exe',
           'svchost.exe','explorer.exe','conhost.exe','taskhostw.exe','dwm.exe',
           'ctfmon.exe','spoolsv.exe','searchindexer.exe','wuauclt.exe',
           'lsm.exe','wininit.exe','taskeng.exe','dllhost.exe','rundll32.exe',
           'msiexec.exe','sihost.exe','fontdrvhost.exe'
       )
       AND NOT (
           LOWER(path) LIKE '%%/windows/system32%%' OR
           LOWER(path) LIKE '%%/windows/winsxs%%' OR
           LOWER(path) LIKE '%%/windows/servicing/lcu/%%' OR
           LOWER(path) LIKE '%%/windows%%'
       )
       """
   )

   # ----------------------------------------------------------
   # 6️⃣ High-entropy files in suspicious paths
   # ----------------------------------------------------------
   run_analysis_query(
       "🧠 High-Entropy Files in Suspicious Paths",
       """
       SELECT filename AS Filename,
              path AS Path,
              sha256 AS "SHA-256",
              ROUND(CAST(entropy AS NUMERIC), 2) AS Entropy,
              suspicious_structure AS "Suspicious_Path"
       FROM files
       WHERE entropy > 7.5 AND suspicious_structure = 'yes'
       ORDER BY entropy DESC
       LIMIT 100
       """
   )

   # ----------------------------------------------------------
   # 7️⃣ IFEO debugger registry entries
   # ----------------------------------------------------------
   run_analysis_query(
       "🧬 Suspicious IFEO Debuggers (Registry Scan)",
       """
       SELECT hostname AS Host,
              key_path AS "Key Path",
              value_name AS "Value Name",
              value_data AS "Value Data",
              rp_timestamp AS "RP Timestamp"
       FROM registry_scan
       WHERE key_path LIKE '%%Image File Execution Options%%'
         AND value_name = 'Debugger'
         AND (
             value_data LIKE '%%cmd.exe%%' OR
             value_data LIKE '%%powershell.exe%%' OR
             value_data LIKE '%%wscript.exe%%' OR
             value_data LIKE '%%cscript.exe%%' OR
             value_data LIKE '%%\\\\Users\\\\%%' OR
             value_data LIKE '%%\\\\Temp\\\\%%' OR
             value_data LIKE '%%\\\\AppData\\\\%%' OR
             value_data LIKE '%%rat.exe%%' OR
             value_data LIKE '%%payload%%' OR
             value_data LIKE '%%\\\\Tasks\\\\%%' OR
             value_data LIKE '%%\\\\explorer.exe%%' OR
             value_data LIKE '%%\\\\svchost.exe%%'
         )
       LIMIT 100
       """
   )

   if not filtered.empty and "filetype" in filtered.columns:
       # 1️⃣ Make the PE-timestamp column timezone-naïve
       pe_ts = pd.to_datetime(filtered["pe_timestamp"], errors="coerce")
       if pe_ts.dt.tz is not None:
           # Drop any tz information (convert to naive UTC)
           pe_ts = pe_ts.dt.tz_convert(None).dt.tz_localize(None)

       # 2️⃣ Cut-off date (naïve Timestamp)
       cutoff_date = pd.Timestamp("2024-06-15")   # no tz

       # 3️⃣ Build the mask – all three conditions must hold
       pe_mask = (
           (filtered["filetype"] == "executable") &
           (pd.to_numeric(filtered["entropy"], errors="coerce") >= 7.9) &
           (pe_ts >= cutoff_date)
       )

       # 4️⃣ Apply the mask
       pe_filtered = filtered[pe_mask]

       # ----- UI for the filtered PE files -----
       st.markdown("### 🧬 High-Entropy Executables with Recent PE Metadata")
       if pe_filtered.empty:
           st.info("No high-entropy executables with recent PE timestamps found.")
       else:
           # Show top 100 by entropy
           pe_filtered = pe_filtered.sort_values("entropy", ascending=False).head(100)

           # Add VirusTotal links
           pe_filtered["VT Link"] = pe_filtered["sha256"].apply(
               lambda h: f"https://www.virustotal.com/gui/file/{h}"
           )

           # Friendly column names
           pe_view = pe_filtered.rename(columns={
               "hostname": "Host",
               "filename": "Filename",
               "path": "Path",
               "rp_timestamp": "RP Timestamp",
               "magic_type": "Magic Type",
               "pe_timestamp": "PE Timestamp",
               "pe_sections": "PE Sections",
               "entropy": "Entropy",
               "sha256": "SHA-256",
           })

           # Keep only columns that actually exist
           display_cols = [
               c for c in [
                   "Host", "Filename", "Path", "RP Timestamp", "Entropy",
                   "Magic Type", "PE Timestamp", "PE Sections", "SHA-256", "VT Link"
               ] if c in pe_view.columns
           ]

           st.dataframe(pe_view[display_cols], use_container_width=True)


           # ----- YARA rule generator for a selected file (Form-Version) -----
           if not pe_view.empty:
               with st.form(key="yara_form"):
                   sel_file = st.selectbox(
                       "Select a file to generate a YARA rule",
                       pe_view["Filename"].dropna().unique(),
                       key="yara_selected_file"
                   )
                   generate_btn = st.form_submit_button("🚀 Generate YARA rule")

               if generate_btn and sel_file:
                   row = pe_view[pe_view["Filename"] == sel_file].iloc[0]

                   with st.spinner("Generating rule…"):
                       rule = generate_yara_rule(
                           filename=row["Filename"],
                           sha256=row["SHA-256"],
                           pe_sections=row.get("PE Sections"),
                           size=row.get("size")
                       )

                       if rule:
                           st.success("✅ Rule generated")
                           st.text_area("YARA Rule", rule, height=250)
                           st.download_button(
                               label="💾 Download .yar",
                               data=rule,
                               file_name=f"{row['Filename']}_rule.yar",
                               mime="text/plain"
                           )
                       else:
                           st.warning("⚠️ No rule generated – no unusual PE sections found.")

# ==================== Events Tab ====================
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

# -------------------- Footer --------------------
st.markdown("---")
now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
st.caption(f"🕵🏾‍♀️ Retro Hunter – powered by Veeam Data Integration API ({now_str}) – Version-2.3 PostgreSQL")
st.caption("🤖 Some logic and optimizations were assisted using AI tools.")
