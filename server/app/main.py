import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .database.db import init_db
from .api import clients, devices, requests, events

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

# Ensure database schema is created immediately on module import
init_db()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and tables
    init_db()
    yield

app = FastAPI(
    title="USBIPS Management Server",
    description="Centralized Hardware Access-Control & Security Telemetry Server for USBIPS",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Static Files & Templates
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount Routers
app.include_router(clients.router)
app.include_router(devices.router)
app.include_router(requests.router)
app.include_router(events.router)

@app.get("/", tags=["Dashboard UI"])
async def serve_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": "USBIPS Central Management Server"}

@app.post("/api/device/check", tags=["Devices & Master Allowlist"])
async def check_device_alias(data: devices.DeviceCheckRequest):
    return devices.check_or_request_device(data)
