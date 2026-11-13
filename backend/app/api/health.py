from fastapi import APIRouter
from ..config import settings

router = APIRouter(tags=["Health"])

@router.get("/health")
def get_health():
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "detection_engine_version": settings.DETECTION_ENGINE_VERSION,
        "ssrf_protection": "enabled",
        "mode": "standalone-soc"
    }

