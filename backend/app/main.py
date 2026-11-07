from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.database import engine, Base, SessionLocal
from app.seed_data import seed_sample_data
from app.routers import (
    health,
    investigations,
    messages,
    dashboard,
    threat_reports,
    registry,
    correlation
)

# Create tables on load
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)
    
    # Seed initial benchmark dataset
    db = SessionLocal()
    try:
        seed_sample_data(db)
    finally:
        db.close()
        
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "TrustLens AI - AI-Powered Web Threat Detection & Digital Trust Intelligence.\n"
        "Investigate phishing URLs, website impersonation, TLS trust, scam messages, "
        "passive security posture, and verify immutable threat reports in the cryptographic registry."
    ),
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In development allow all for smooth dev preview, configurable via settings
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handler to ensure clean JSON responses
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log cleanly without secrets
    err_type = type(exc).__name__
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": f"A backend processing error occurred: {err_type}",
            "details": str(exc)[:200]
        }
    )

# Register Routers
app.include_router(health.router)
app.include_router(investigations.router)
app.include_router(messages.router)
app.include_router(dashboard.router)
app.include_router(threat_reports.router)
app.include_router(registry.router)
app.include_router(correlation.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
