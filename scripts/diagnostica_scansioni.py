"""Stato delle ultime scansioni. Eseguito dentro il container API da `make doctor`.

Risponde alla domanda «perche' la scansione non parte»: se manca l'id del task
Celery l'accodamento non e' avvenuto, se lo stato resta `queued` con l'id
presente nessun worker l'ha presa in carico.
"""
from __future__ import annotations

from sqlalchemy import desc, select

from app.core.db import session_scope
from app.models.scanning import Scan


def main() -> None:
    with session_scope() as db:
        righe = db.execute(
            select(Scan).order_by(desc(Scan.created_at)).limit(10)).scalars().all()
        if not righe:
            print("  NESSUNA scansione presente nel database")
            return
        for scan in righe:
            print(f"  {str(scan.id)[:8]}  {scan.profile_key:18s} {scan.status:10s} "
                  f"mock={str(scan.mock_mode):5s} "
                  f"accodata={'si' if scan.celery_task_id else 'NO'}  "
                  f"fase={scan.current_stage or '-'} {scan.progress_percent or 0}%")
            if scan.error_message:
                print(f"      errore: {scan.error_message[:200]}")


if __name__ == "__main__":
    main()
