from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from dotenv import load_dotenv
import os

load_dotenv()
# Make sure to change the Key in the .env file
API_KEY = os.getenv("MCP_API_KEY")
API_KEY_NAME = "X-API-Key"

app = FastAPI(
   title="Retro Hunter MCP Server",
   version="1.0"
)

# Apply API 
@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
   # Public endpoints (no auth)
   if request.url.path in ["/", "/docs", "/redoc", "/openapi.json"]:
       return await call_next(request)

   # Check API key
   api_key = request.headers.get(API_KEY_NAME)
   if api_key != API_KEY:
       return JSONResponse(status_code=403, content={"detail": "Forbidden"})

   return await call_next(request)

def custom_openapi():
   if app.openapi_schema:
       return app.openapi_schema
   openapi_schema = get_openapi(
       title=app.title,
       version=app.version,
       description="Retro Hunter MCP API",
       routes=app.routes,
   )
   openapi_schema["components"]["securitySchemes"] = {
       "APIKeyHeader": {
           "type": "apiKey",
           "name": API_KEY_NAME,
           "in": "header"
       }
   }
   openapi_schema["security"] = [{"APIKeyHeader": []}]
   app.openapi_schema = openapi_schema
   return app.openapi_schema

app.openapi = custom_openapi

@app.get("/")
def healthcheck():
   return {"status": "Retro Hunter MCP is ready to serve!"}

from mcp_logic import load_modules
load_modules(app)
analyst@retro-hunter:~/version22/mcp_server$
