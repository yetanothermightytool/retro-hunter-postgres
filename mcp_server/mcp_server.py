from fastapi import FastAPI, HTTPException, Request
from mcp_logic import load_tools
import os

app = FastAPI(
   title="Retro Hunter MCP Server",
   version="1.0"
)

# Dynamically load tools from /tools
load_tools(app)

@app.get("/")
def healthcheck():
   return {"status": "Retro Hunter MCP is ready to serve."}
