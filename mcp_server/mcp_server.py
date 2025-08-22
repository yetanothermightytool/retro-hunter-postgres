from fastapi import FastAPI, HTTPException, Request
from mcp_logic import load_modules
import os

app = FastAPI(
   title="Retro Hunter MCP Server",
   version="1.0"
)

# Dynamically load modules from /modules
load_modules(app)

@app.get("/")
def healthcheck():
   return {"status": "Retro Hunter MCP is ready to serve"}
