from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Setting
from ..schemas import SettingsUpdate

router = APIRouter(prefix="/settings", tags=["Settings"])

@router.get("")
def get_all_settings(db: Session = Depends(get_db)):
    settings_records = db.query(Setting).all()
    results = {s.setting_key: s.setting_value for s in settings_records}

    # Defaults if not present
    defaults = {
        "theme": "dark",
        "engine_version": "3.1.0-SOC",
        "store_email_body": "false",
        "notification_sound": "true",
        "alert_threshold": "40",
        "auto_export_pdf": "false",
        "telemetry_sharing": "false",
        "retention_days": "90"
    }
    for k, v in defaults.items():
        if k not in results:
            results[k] = v

    return results


@router.put("")
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db)):
    updates = payload.settings
    for key, value in updates.items():
        existing = db.query(Setting).filter(Setting.setting_key == key).first()
        if existing:
            existing.setting_value = str(value)
        else:
            db.add(Setting(setting_key=key, setting_value=str(value)))
    db.commit()
    return {"message": "Settings updated successfully", "updated_keys": list(updates.keys())}

