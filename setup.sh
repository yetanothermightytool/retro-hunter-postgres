#!/bin/bash
echo "🛠️ Retro Hunter Environment Setup"

# ARGUMENT CHECK
if [ $# -lt 2 ]; then
 echo "ℹ️ Usage: ./setup.sh <malwarebazaar.csv> <project_directory>"
 exit 1
fi

MALWARE_CSV="$1"
PROJECT_DIR="$2"

# PYTHON MODULE CHECK
echo "🐍 Checking required Python modules..."
REQUIRED_MODULES=(colorama requests dateutil Evtx magic pefile psycopg2 dotenv)
MISSING_MODULES=()
for module in "${REQUIRED_MODULES[@]}"; do
 python3 -c "import $module" 2>/dev/null || MISSING_MODULES+=("$module")
done
python3 -c "import yara" 2>/dev/null || MISSING_MODULES+=("yara-python")
if [ ${#MISSING_MODULES[@]} -ne 0 ]; then
 echo "❌ Missing Python modules:"
 for m in "${MISSING_MODULES[@]}"; do echo "  - $m"; done
 echo "💡 Install with: pip3 install ${MISSING_MODULES[*]}"
 exit 1
else
 echo "✅ All Python modules are present."
fi

# VERIFY CSV FILE
if [ ! -f "$MALWARE_CSV" ]; then
 echo "❌ File not found: $MALWARE_CSV"
 exit 1
fi
echo "📄 Found malwarebazaar.csv"

# CREATE PROJECT DIRECTORY
if [ ! -d "$PROJECT_DIR" ]; then
 echo "📁 Creating project directory $PROJECT_DIR"
 mkdir -p "$PROJECT_DIR"
else
 echo "📂 Using existing project directory: $PROJECT_DIR"
fi
cd "$PROJECT_DIR" || exit 1

# CLONE REPO
if [ ! -d ".git" ]; then
 echo "🌐 Cloning Retro Hunter GitHub repository..."
 git clone https://github.com/yetanothermightytool/retro-hunter-postgres.git . || {
   echo "❌ Failed to clone GitHub repo"
   exit 1
 }
else
 echo "🔄 Git repository already present. Aborting setup."
 exit 1
fi

# COPY CSV
echo "📦 Copying malwarebazaar.csv..."
cp "$MALWARE_CSV" malwarebazaar.csv

# CHECK LOCAL FILES
echo "🔍 Checking required local import files..."
REQUIRED=(import_lolbas.py lolbin.csv import_malwarebazaar.py)
for f in "${REQUIRED[@]}"; do
 [ ! -f "$f" ] && echo "❌ Missing: $f" && exit 1
done

# CREATE .env AND .env.local
read -p "🧑 Enter PostgreSQL username: " PG_USER
read -s -p "🔐 Enter PostgreSQL password: " PG_PASS
echo ""

cat > .env <<EOF
POSTGRES_USER=$PG_USER
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=retro-hunter
POSTGRES_HOST=db
POSTGRES_PORT=5432
EOF

cat > .env.local <<EOF
POSTGRES_USER=$PG_USER
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=retro-hunter
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
EOF

chmod 600 .env .env.local
echo "✅ .env and .env.local created (secure)."

# START DATABASE CONTAINER
echo "🐘 Starting PostgreSQL container..."
sudo docker compose -f docker-compose.yml up -d db

echo "⏳ Waiting for PostgreSQL to become available..."
until sudo docker exec $(sudo docker compose ps -q db) pg_isready -U "$PG_USER" > /dev/null 2>&1; do
 sleep 1
done
echo "✅ PostgreSQL is running."


# Import DB files
echo "🦠 Importing MalwareBazaar and LOLBAS data..."
python3 import_lolbas.py || { echo "❌ LOLBAS import failed"; exit 1; }
python3 import_malwarebazaar.py || { echo "❌ MalwareBazaar import failed"; exit 1; }

# Ask for VBR Server Config
read -p "🌐 Enter VBR Server: " VBR_SERVER
read -p "👤 Enter Veeam REST API username: " REST_USER

if [ -z "$VBR_SERVER" ] || [ -z "$REST_USER" ]; then
 echo "❌ VBR Server and REST API User are required."
 exit 1
fi

sed -i "s|__REPLACE_VBR_SERVER__|$VBR_SERVER|g" retro-hunter.py
sed -i "s|__REPLACE_REST_API_USER__|$REST_USER|g" retro-hunter.py
echo "✅ Patched retro-hunter.py"

# CREATE FERNET FILES
echo "🔐 Generating Fernet key files..."
cp fernet/create-fernet-files.py . || { echo "❌ Missing create-fernet-files.py"; exit 1; }
python3 create-fernet-files.py || { echo "❌ Fernet key generation failed"; exit 1; }
rm -rf fernet/
echo "✅ Fernet key generated."

# === Generate self-signed SSL certificate for Streamlit ===
echo "🔐 Generating self-signed SSL certificate for Streamlit..."

CERT_DIR="certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
   echo "⚠️  SSL certificate already exists – skipping generation."
else
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
       -keyout "$KEY_FILE" \
       -out "$CERT_FILE" \
       -subj "/CN=localhost" > /dev/null 2>&1

   echo "✅ Self-signed certificate created at $CERT_DIR/"
   echo "⚠️  This is not secure for production use!"
fi

# START STREAMLIT DASHBOARD
read -p "📊 Start Streamlit UI in Docker now? [y/N]: " UI_CONFIRM
if [[ "$UI_CONFIRM" =~ ^[Yy]$ ]]; then
 echo "🚀 Starting Streamlit Dashboard..."
 sudo docker compose -f docker-compose.yml up -d
 echo "✅ Streamlit is running at: https://localhost:8501"
else
 echo "⚠️ Skipped UI startup."
fi

# CLEANUP
echo "🧹 Cleaning up temporary import files..."
rm -f import_lolbas.py lolbin.csv malwarebazaar.csv create-fernet-files.py
rm -rf Images

echo "✅ Setup complete!"

