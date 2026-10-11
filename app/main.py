"""
FastAPI app entrypoint. Run locally with: uvicorn app.main:app --reload
"""
from fastapi import FastAPI

from app.api import routes_health, routes_ping

app = FastAPI(title="Vetra AI service")
app.include_router(routes_health.router)
app.include_router(routes_ping.router)
