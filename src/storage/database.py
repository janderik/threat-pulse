from __future__ import annotations

import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Optional

from src.models.ioc import IOC, Confidence, IOCType
from src.models.threat import Threat, ThreatStatus

logger = logging.getLogger(__name__)


class Database:
    """Storage backend for threat intelligence data. Supports SQLite (default) and PostgreSQL."""

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or os.getenv("DATABASE_URL", "")
        self._conn: Optional[sqlite3.Connection] = None
        self._use_postgres = "postgresql" in self.db_url

        if not self._use_postgres:
            db_path = self._resolve_sqlite_path()
            logger.info("Using SQLite database at: %s", db_path)
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._init_sqlite()
        else:
            logger.info("Using PostgreSQL database (config via DATABASE_URL)")
            self._init_postgres()

    def _resolve_sqlite_path(self) -> str:
        if self.db_url and self.db_url.startswith("sqlite:///"):
            return self.db_url[len("sqlite:///"):]
        return str(Path("data") / "threatpulse.db")

    def _init_sqlite(self):
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                description TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                confidence TEXT NOT NULL DEFAULT 'medium',
                tags TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                severity REAL NOT NULL DEFAULT 5.0,
                mitre_id TEXT,
                reference_urls TEXT NOT NULL DEFAULT '[]',
                raw_data TEXT,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
            CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
            CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
            CREATE INDEX IF NOT EXISTS idx_iocs_confidence ON iocs(confidence);
            CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(active);

            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'new',
                source TEXT NOT NULL DEFAULT 'manual',
                ioc_ids TEXT NOT NULL DEFAULT '[]',
                mitre_techniques TEXT NOT NULL DEFAULT '[]',
                mitre_tactic TEXT,
                score REAL NOT NULL DEFAULT 0.0,
                affected_systems TEXT NOT NULL DEFAULT '[]',
                actor TEXT,
                campaign TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                notes TEXT NOT NULL DEFAULT '[]',
                raw_data TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_threats_name ON threats(name);
            CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
            CREATE INDEX IF NOT EXISTS idx_threats_score ON threats(score);
        """)
        self._conn.commit()
        cur.close()

    def _init_postgres(self):
        try:
            from sqlalchemy import create_engine, text
            self._pg_engine = create_engine(self.db_url)
            with self._pg_engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS iocs (
                        id VARCHAR(36) PRIMARY KEY,
                        type VARCHAR(20) NOT NULL,
                        value TEXT NOT NULL,
                        description TEXT,
                        source VARCHAR(100) NOT NULL DEFAULT 'manual',
                        confidence VARCHAR(20) NOT NULL DEFAULT 'medium',
                        tags TEXT NOT NULL DEFAULT '[]',
                        first_seen TIMESTAMP NOT NULL,
                        last_seen TIMESTAMP NOT NULL,
                        severity REAL NOT NULL DEFAULT 5.0,
                        mitre_id VARCHAR(50),
                        reference_urls TEXT NOT NULL DEFAULT '[]',
                        raw_data TEXT,
                        active BOOLEAN NOT NULL DEFAULT TRUE
                    );
                    CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
                    CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
                    CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
                    CREATE INDEX IF NOT EXISTS idx_iocs_confidence ON iocs(confidence);
                    CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(active);

                    CREATE TABLE IF NOT EXISTS threats (
                        id VARCHAR(36) PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        status VARCHAR(20) NOT NULL DEFAULT 'new',
                        source VARCHAR(100) NOT NULL DEFAULT 'manual',
                        ioc_ids TEXT NOT NULL DEFAULT '[]',
                        mitre_techniques TEXT NOT NULL DEFAULT '[]',
                        mitre_tactic VARCHAR(100),
                        score REAL NOT NULL DEFAULT 0.0,
                        affected_systems TEXT NOT NULL DEFAULT '[]',
                        actor VARCHAR(200),
                        campaign VARCHAR(200),
                        created_at TIMESTAMP NOT NULL,
                        updated_at TIMESTAMP NOT NULL,
                        tags TEXT NOT NULL DEFAULT '[]',
                        notes TEXT NOT NULL DEFAULT '[]',
                        raw_data TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_threats_name ON threats(name);
                    CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
                    CREATE INDEX IF NOT EXISTS idx_threats_score ON threats(score);
                """))
                conn.commit()
        except Exception as e:
            logger.error("Failed to initialize PostgreSQL: %s. Falling back to SQLite.", e)
            self._use_postgres = False
            db_path = self._resolve_sqlite_path()
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._init_sqlite()

    # --- IOC operations ---

    def store_ioc(self, ioc: IOC) -> IOC:
        if self._use_postgres:
            return self._store_ioc_pg(ioc)
        return self._store_ioc_sqlite(ioc)

    def _store_ioc_sqlite(self, ioc: IOC) -> IOC:
        cur = self._conn.cursor()
        cur.execute(
            """INSERT OR REPLACE INTO iocs
               (id, type, value, description, source, confidence, tags,
                first_seen, last_seen, severity, mitre_id, reference_urls, raw_data, active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ioc.id, ioc.type.value, ioc.value, ioc.description,
                ioc.source, ioc.confidence.value,
                json.dumps(ioc.tags),
                ioc.first_seen.isoformat(), ioc.last_seen.isoformat(),
                ioc.severity, ioc.mitre_id,
                json.dumps(ioc.reference_urls),
                json.dumps(ioc.raw_data) if ioc.raw_data else None,
                1 if ioc.active else 0,
            ),
        )
        self._conn.commit()
        cur.close()
        return ioc

    def _store_ioc_pg(self, ioc: IOC) -> IOC:
        from sqlalchemy import text
        with self._pg_engine.connect() as conn:
            conn.execute(
                text("""INSERT INTO iocs
                    (id, type, value, description, source, confidence, tags,
                     first_seen, last_seen, severity, mitre_id, reference_urls, raw_data, active)
                    VALUES (:id, :type, :value, :desc, :src, :conf, :tags,
                            :first, :last, :sev, :mitre, :refs, :raw, :active)
                    ON CONFLICT (id) DO UPDATE SET
                        last_seen = EXCLUDED.last_seen,
                        severity = EXCLUDED.severity,
                        active = EXCLUDED.active"""),
                {
                    "id": ioc.id, "type": ioc.type.value, "value": ioc.value,
                    "desc": ioc.description, "src": ioc.source,
                    "conf": ioc.confidence.value,
                    "tags": json.dumps(ioc.tags),
                    "first": ioc.first_seen.isoformat(),
                    "last": ioc.last_seen.isoformat(),
                    "sev": ioc.severity, "mitre": ioc.mitre_id,
                    "refs": json.dumps(ioc.reference_urls),
                    "raw": json.dumps(ioc.raw_data) if ioc.raw_data else None,
                    "active": ioc.active,
                },
            )
            conn.commit()
        return ioc

    def store_iocs(self, iocs: list[IOC]) -> list[IOC]:
        return [self.store_ioc(ioc) for ioc in iocs]

    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        if self._use_postgres:
            return self._get_ioc_pg(ioc_id)
        return self._get_ioc_sqlite(ioc_id)

    def _get_ioc_sqlite(self, ioc_id: str) -> Optional[IOC]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM iocs WHERE id = ?", (ioc_id,))
        row = cur.fetchone()
        cur.close()
        return self._row_to_ioc(row) if row else None

    def _get_ioc_pg(self, ioc_id: str) -> Optional[IOC]:
        from sqlalchemy import text
        with self._pg_engine.connect() as conn:
            row = conn.execute(text("SELECT * FROM iocs WHERE id = :id"), {"id": ioc_id}).fetchone()
            if row is None:
                return None
            return self._pg_row_to_ioc(row._mapping)

    def search_iocs(
        self,
        value: Optional[str] = None,
        ioc_type: Optional[IOCType] = None,
        source: Optional[str] = None,
        confidence: Optional[Confidence] = None,
        active_only: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IOC]:
        if self._use_postgres:
            return self._search_iocs_pg(value, ioc_type, source, confidence, active_only, limit, offset)
        return self._search_iocs_sqlite(value, ioc_type, source, confidence, active_only, limit, offset)

    def _search_iocs_sqlite(
        self, value, ioc_type, source, confidence, active_only, limit, offset
    ) -> list[IOC]:
        query = "SELECT * FROM iocs WHERE 1=1"
        params: list = []

        if value:
            query += " AND value LIKE ?"
            params.append(f"%{value}%")
        if ioc_type:
            query += " AND type = ?"
            params.append(ioc_type.value)
        if source:
            query += " AND source = ?"
            params.append(source)
        if confidence:
            query += " AND confidence = ?"
            params.append(confidence.value)
        if active_only:
            query += " AND active = 1"

        query += " ORDER BY severity DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = self._conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        cur.close()
        return [self._row_to_ioc(r) for r in rows]

    def _search_iocs_pg(self, value, ioc_type, source, confidence, active_only, limit, offset):
        from sqlalchemy import text
        query = "SELECT * FROM iocs WHERE 1=1"
        params = {}

        if value:
            query += " AND value LIKE :value"
            params["value"] = f"%{value}%"
        if ioc_type:
            query += " AND type = :type"
            params["type"] = ioc_type.value
        if source:
            query += " AND source = :source"
            params["source"] = source
        if confidence:
            query += " AND confidence = :confidence"
            params["confidence"] = confidence.value
        if active_only:
            query += " AND active = TRUE"

        query += " ORDER BY severity DESC LIMIT :limit OFFSET :offset"
        params.update({"limit": limit, "offset": offset})

        with self._pg_engine.connect() as conn:
            rows = conn.execute(text(query), params).fetchall()
            return [self._pg_row_to_ioc(r._mapping) for r in rows]

    def delete_ioc(self, ioc_id: str) -> bool:
        if self._use_postgres:
            from sqlalchemy import text
            with self._pg_engine.connect() as conn:
                result = conn.execute(text("DELETE FROM iocs WHERE id = :id"), {"id": ioc_id})
                conn.commit()
                return result.rowcount > 0

        cur = self._conn.cursor()
        cur.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
        deleted = cur.rowcount > 0
        self._conn.commit()
        cur.close()
        return deleted

    def count_iocs(self) -> int:
        if self._use_postgres:
            from sqlalchemy import text
            with self._pg_engine.connect() as conn:
                row = conn.execute(text("SELECT COUNT(*) as cnt FROM iocs")).fetchone()
                return row._mapping["cnt"]

        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM iocs")
        row = cur.fetchone()
        cur.close()
        return row["cnt"]

    # --- Threat operations ---

    def store_threat(self, threat: Threat) -> Threat:
        if self._use_postgres:
            return self._store_threat_pg(threat)
        return self._store_threat_sqlite(threat)

    def _store_threat_sqlite(self, threat: Threat) -> Threat:
        cur = self._conn.cursor()
        cur.execute(
            """INSERT OR REPLACE INTO threats
               (id, name, description, status, source, ioc_ids, mitre_techniques,
                mitre_tactic, score, affected_systems, actor, campaign,
                created_at, updated_at, tags, notes, raw_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                threat.id, threat.name, threat.description,
                threat.status.value, threat.source,
                json.dumps(threat.ioc_ids), json.dumps(threat.mitre_techniques),
                threat.mitre_tactic, threat.score,
                json.dumps(threat.affected_systems), threat.actor, threat.campaign,
                threat.created_at.isoformat(), threat.updated_at.isoformat(),
                json.dumps(threat.tags), json.dumps(threat.notes),
                json.dumps(threat.raw_data) if threat.raw_data else None,
            ),
        )
        self._conn.commit()
        cur.close()
        return threat

    def _store_threat_pg(self, threat: Threat) -> Threat:
        from sqlalchemy import text
        with self._pg_engine.connect() as conn:
            conn.execute(
                text("""INSERT INTO threats
                    (id, name, description, status, source, ioc_ids, mitre_techniques,
                     mitre_tactic, score, affected_systems, actor, campaign,
                     created_at, updated_at, tags, notes, raw_data)
                    VALUES (:id, :name, :desc, :status, :src, :ioc_ids, :mitre_techs,
                            :mitre_tactic, :score, :affected, :actor, :campaign,
                            :created, :updated, :tags, :notes, :raw)
                    ON CONFLICT (id) DO UPDATE SET
                        status = EXCLUDED.status,
                        score = EXCLUDED.score,
                        updated_at = EXCLUDED.updated_at"""),
                {
                    "id": threat.id, "name": threat.name, "desc": threat.description,
                    "status": threat.status.value, "src": threat.source,
                    "ioc_ids": json.dumps(threat.ioc_ids),
                    "mitre_techs": json.dumps(threat.mitre_techniques),
                    "mitre_tactic": threat.mitre_tactic, "score": threat.score,
                    "affected": json.dumps(threat.affected_systems),
                    "actor": threat.actor, "campaign": threat.campaign,
                    "created": threat.created_at.isoformat(),
                    "updated": threat.updated_at.isoformat(),
                    "tags": json.dumps(threat.tags), "notes": json.dumps(threat.notes),
                    "raw": json.dumps(threat.raw_data) if threat.raw_data else None,
                },
            )
            conn.commit()
        return threat

    def get_threat(self, threat_id: str) -> Optional[Threat]:
        if self._use_postgres:
            return self._get_threat_pg(threat_id)
        return self._get_threat_sqlite(threat_id)

    def _get_threat_sqlite(self, threat_id: str) -> Optional[Threat]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM threats WHERE id = ?", (threat_id,))
        row = cur.fetchone()
        cur.close()
        return self._row_to_threat(row) if row else None

    def _get_threat_pg(self, threat_id: str) -> Optional[Threat]:
        from sqlalchemy import text
        with self._pg_engine.connect() as conn:
            row = conn.execute(text("SELECT * FROM threats WHERE id = :id"), {"id": threat_id}).fetchone()
            if row is None:
                return None
            return self._pg_row_to_threat(row._mapping)

    def search_threats(
        self,
        name: Optional[str] = None,
        status: Optional[ThreatStatus] = None,
        source: Optional[str] = None,
        min_score: float = 0.0,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Threat]:
        if self._use_postgres:
            return self._search_threats_pg(name, status, source, min_score, limit, offset)
        return self._search_threats_sqlite(name, status, source, min_score, limit, offset)

    def _search_threats_sqlite(self, name, status, source, min_score, limit, offset):
        query = "SELECT * FROM threats WHERE score >= ?"
        params: list = [min_score]

        if name:
            query += " AND name LIKE ?"
            params.append(f"%{name}%")
        if status:
            query += " AND status = ?"
            params.append(status.value)
        if source:
            query += " AND source = ?"
            params.append(source)

        query += " ORDER BY score DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = self._conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        cur.close()
        return [self._row_to_threat(r) for r in rows]

    def _search_threats_pg(self, name, status, source, min_score, limit, offset):
        from sqlalchemy import text
        query = "SELECT * FROM threats WHERE score >= :min_score"
        params = {"min_score": min_score}

        if name:
            query += " AND name LIKE :name"
            params["name"] = f"%{name}%"
        if status:
            query += " AND status = :status"
            params["status"] = status.value
        if source:
            query += " AND source = :source"
            params["source"] = source

        query += " ORDER BY score DESC LIMIT :limit OFFSET :offset"
        params.update({"limit": limit, "offset": offset})

        with self._pg_engine.connect() as conn:
            rows = conn.execute(text(query), params).fetchall()
            return [self._pg_row_to_threat(r._mapping) for r in rows]

    def delete_threat(self, threat_id: str) -> bool:
        if self._use_postgres:
            from sqlalchemy import text
            with self._pg_engine.connect() as conn:
                result = conn.execute(text("DELETE FROM threats WHERE id = :id"), {"id": threat_id})
                conn.commit()
                return result.rowcount > 0

        cur = self._conn.cursor()
        cur.execute("DELETE FROM threats WHERE id = ?", (threat_id,))
        deleted = cur.rowcount > 0
        self._conn.commit()
        cur.close()
        return deleted

    def count_threats(self) -> int:
        if self._use_postgres:
            from sqlalchemy import text
            with self._pg_engine.connect() as conn:
                row = conn.execute(text("SELECT COUNT(*) as cnt FROM threats")).fetchone()
                return row._mapping["cnt"]

        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM threats")
        row = cur.fetchone()
        cur.close()
        return row["cnt"]

    # --- Row conversion helpers ---

    def _row_to_ioc(self, row: sqlite3.Row) -> IOC:
        return IOC(
            id=row["id"],
            type=IOCType(row["type"]),
            value=row["value"],
            description=row["description"],
            source=row["source"],
            confidence=Confidence(row["confidence"]),
            tags=json.loads(row["tags"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            severity=row["severity"],
            mitre_id=row["mitre_id"],
            reference_urls=json.loads(row["reference_urls"]) if row["reference_urls"] else [],
            raw_data=json.loads(row["raw_data"]) if row["raw_data"] else None,
            active=bool(row["active"]),
        )

    def _pg_row_to_ioc(self, row) -> IOC:
        return IOC(
            id=row["id"],
            type=IOCType(row["type"]),
            value=row["value"],
            description=row.get("description"),
            source=row["source"],
            confidence=Confidence(row["confidence"]),
            tags=json.loads(row["tags"]) if isinstance(row["tags"], str) else row["tags"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            severity=row["severity"],
            mitre_id=row.get("mitre_id"),
            reference_urls=json.loads(row["reference_urls"]) if isinstance(row["reference_urls"], str) else row["reference_urls"],
            raw_data=json.loads(row["raw_data"]) if isinstance(row["raw_data"], str) else row["raw_data"],
            active=bool(row["active"]),
        )

    def _row_to_threat(self, row: sqlite3.Row) -> Threat:
        return Threat(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            status=ThreatStatus(row["status"]),
            source=row["source"],
            ioc_ids=json.loads(row["ioc_ids"]),
            mitre_techniques=json.loads(row["mitre_techniques"]),
            mitre_tactic=row["mitre_tactic"],
            score=row["score"],
            affected_systems=json.loads(row["affected_systems"]),
            actor=row["actor"],
            campaign=row["campaign"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            tags=json.loads(row["tags"]),
            notes=json.loads(row["notes"]),
        )

    def _pg_row_to_threat(self, row) -> Threat:
        return Threat(
            id=row["id"],
            name=row["name"],
            description=row.get("description"),
            status=ThreatStatus(row["status"]),
            source=row["source"],
            ioc_ids=json.loads(row["ioc_ids"]) if isinstance(row["ioc_ids"], str) else row["ioc_ids"],
            mitre_techniques=json.loads(row["mitre_techniques"]) if isinstance(row["mitre_techniques"], str) else row["mitre_techniques"],
            mitre_tactic=row.get("mitre_tactic"),
            score=row["score"],
            affected_systems=json.loads(row["affected_systems"]) if isinstance(row["affected_systems"], str) else row["affected_systems"],
            actor=row.get("actor"),
            campaign=row.get("campaign"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            tags=json.loads(row["tags"]) if isinstance(row["tags"], str) else row["tags"],
            notes=json.loads(row["notes"]) if isinstance(row["notes"], str) else row["notes"],
        )

    def close(self):
        if self._conn:
            self._conn.close()
