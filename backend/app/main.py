from contextlib import asynccontextmanager
import logging
from secrets import compare_digest
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
        "TrustLens AI - Web Threat Analysis & Digital Trust Demonstrator.\n"
        "Investigate phishing URLs, website impersonation, TLS trust, scam messages, "
        "passive security posture, and verify threat reports in the local cryptographic hash registry."
    ),
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https:\/\/.*\.vercel\.app$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.middleware("http")
async def apply_security_headers_and_access_control(request: Request, call_next):
    protected_api_request = (
        settings.APP_ACCESS_TOKEN
        and request.url.path.startswith("/api/")
        and request.url.path != "/api/health"
        and request.method != "OPTIONS"
    )
    if protected_api_request:
        scheme, separator, supplied_token = request.headers.get("authorization", "").partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not compare_digest(supplied_token, settings.APP_ACCESS_TOKEN)
        ):
            response = JSONResponse(
                status_code=401,
                content={"detail": "A valid bearer token is required."},
                headers={"WWW-Authenticate": "Bearer"},
            )
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response

# Exception handler to ensure clean JSON responses
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    err_type = type(exc).__name__
    logging.getLogger("trustlens").error(
        "Unhandled backend exception (%s) at %s %s",
        err_type,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": "A backend processing error occurred."
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
