"""FastAPI application factory and main app."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import logging
from contextlib import asynccontextmanager

from utils.config import settings
from websocket import websocket_manager


def create_app() -> FastAPI:
    """Create FastAPI application with all middleware and routes."""
    
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        docs_url=settings.docs_url,
        redoc_url=settings.redoc_url,
        description="Professional API Security Testing Tool for Penetration Testers",
    )
    
    # Add middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=settings.allowed_methods,
        allow_headers=settings.allowed_headers,
    )
    
    # Add routers
    from api.routes import health, upload, testing, results, websocket_routes, reports
    
    app.include_router(health.router, prefix=settings.api_prefix, tags=["Health"])
    app.include_router(upload.router, prefix=settings.api_prefix, tags=["Upload"])
    app.include_router(testing.router, prefix=settings.api_prefix, tags=["Testing"])
    app.include_router(results.router, prefix=settings.api_prefix, tags=["Results"])
    app.include_router(reports.router, prefix=settings.api_prefix, tags=["Reports"])  # Added reports router
    app.include_router(websocket_routes.router, prefix=settings.api_prefix, tags=["WebSocket"])
    
    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logging.error(f"Global exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error occurred"}
        )
    
    return app


# Create the application instance
app = create_app()


@app.on_event("startup")
async def startup_event():
    """Application startup tasks."""
    logging.info(f"Starting {settings.app_name} v{settings.version}")
    # Initialize WebSocket manager
    await websocket_manager.start()
    logging.info("WebSocket manager started")


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks."""
    logging.info("Shutting down API Security Tester")
    # Stop WebSocket manager
    await websocket_manager.stop()
    logging.info("WebSocket manager stopped")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="info" if not settings.debug else "debug"
    )