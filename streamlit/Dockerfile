FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && \
   apt-get upgrade -y && \
   apt-get install -y --no-install-recommends \
       build-essential \
       yara && \
   apt-get clean && \
   rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
COPY app.py ./
# COPY certs ./certs/
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8501
CMD ["streamlit", "run", "app.py", \
   "--server.port=8501", \
   "--server.enableCORS=true", \
   "--server.headless=true", \
   "--server.runOnSave=true", \
   "--server.sslCertFile=/app/certs/cert.pem", \
   "--server.sslKeyFile=/app/certs/key.pem"]
