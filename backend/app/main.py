from contextlib import asynccontextmanager
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from .config import settings
from .database import engine, Base, SessionLocal, run_migrations
from .services.seed_data import seed_database_if_empty
from .api import (
    health,
    scan,
    dashboard,
    history,
    threats,
    reports,
    quiz,
    settings as api_settings,
    gmail,
    campaigns,
    attachments,
    timeline,
    ai
)

FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"

# Execute safe schema migrations for new columns
run_migrations()
Base.metadata.create_all(bind=engine)
db_init = SessionLocal()
try:
    seed_database_if_empty(db_init)
finally:
    db_init.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database tables and initial seed data on startup
    run_migrations()
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database_if_empty(db)
    finally:
        db.close()
    yield

app = FastAPI(
    title="PhishGuard Threat Intelligence API",
    version=settings.APP_VERSION,
    description="AI-Powered Phishing Detection & Threat Intelligence Command Center API",
    lifespan=lifespan
)

# Strict CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Register API Routers under /api
app.include_router(health.router, prefix="/api")
app.include_router(scan.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(history.router, prefix="/api")
app.include_router(threats.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(quiz.router, prefix="/api")
app.include_router(api_settings.router, prefix="/api")
app.include_router(gmail.router, prefix="/api")
app.include_router(campaigns.router, prefix="/api")
app.include_router(attachments.router, prefix="/api")
app.include_router(timeline.router, prefix="/api")
app.include_router(ai.router, prefix="/api")

if os.getenv("VERCEL"):
    app.frontend(
        "/",
        directory=str(FRONTEND_DIST),
        fallback="index.html",
        check_dir=False,
    )
else:
    @app.get("/")
    def root():
        frontend_index = FRONTEND_DIST / "index.html"
        if frontend_index.is_file():
            return FileResponse(frontend_index)
        return {
            "platform": "PhishGuard",
            "description": "AI-Powered Phishing Detection & Threat Intelligence Platform",
            "status": "operational",
            "api_docs": "/docs"
        }

    @app.get("/{path:path}")
    def serve_frontend(path: str):
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")

        frontend_index = FRONTEND_DIST / "index.html"
        if not frontend_index.is_file():
            raise HTTPException(status_code=404, detail="Not Found")

        frontend_root = FRONTEND_DIST.resolve()
        requested_file = (FRONTEND_DIST / path).resolve()
        if not requested_file.is_relative_to(frontend_root):
            raise HTTPException(status_code=404, detail="Not Found")
        if requested_file.is_file():
            return FileResponse(requested_file)
        return FileResponse(frontend_index)
