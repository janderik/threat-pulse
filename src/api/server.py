from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import router
from src.storage.database import Database

logger = logging.getLogger(__name__)

db: Database = Database()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ThreatPulse API starting up")
    yield
    logger.info("ThreatPulse API shutting down")
    db.close()


app = FastAPI(
    title="ThreatPulse API",
    description="Open-source Threat Intelligence Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
