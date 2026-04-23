"""
SQLite persistence for processed GitLab security CI jobs.

Used to avoid sending duplicate ``VULNERABILITY_SCAN`` / ``VULNERABILITY_FINDING`` events
when the same job id is seen again on later polls.
"""

import sqlite3
from typing import Any

from dynatrace_extension.sdk.extension import extension_logger as logger


class JobDatabase:
    """
    Context manager around a SQLite DB storing ingested job ids per group/project.

    Responsibility:
        On ``sync_jobs``, insert new job ids and return only jobs that were not previously stored.
    """

    TABLE_NAME = "job_history"

    def __init__(self, db_name: str = "jobs_scan_history.db") -> None:
        """
        Args:
            db_name: SQLite file path (created next to the extension working directory unless absolute).
        """
        self.db_name = db_name
        self.logger = logger
        self.conn: sqlite3.Connection | None = None
        self.cursor: sqlite3.Cursor | None = None

    def __enter__(self) -> "JobDatabase":
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self._init_db()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.conn:
            self.conn.commit()
            self.conn.close()

    def _init_db(self) -> None:
        assert self.cursor is not None
        self.cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_NAME} (
                job_id TEXT PRIMARY KEY,
                group_name TEXT,
                project_path TEXT,
                started TEXT,
                ended TEXT,
                status TEXT
            )
        """)

    def sync_jobs(self, api_data: list[dict[str, Any]] | None, group_name: str, project_path: str) -> list[dict[str, Any]]:
        """
        Args:
            api_data: One batch of jobs for one project (e.g. a single GitLab list-jobs page after filtering).
                Callers may invoke this repeatedly per project to avoid loading all pages into memory at once.
            group_name: Group identifier string stored with each row.
            project_path: Project path stored with each row.

        Returns:
            Only the job dicts whose ids were not already present in the database; new ids are inserted.
        """
        if not isinstance(api_data, list) or not api_data:
            return []
        job_ids = [str(job.get("id")) for job in api_data if job.get("id") is not None]
        if not job_ids:
            return []
        existing_ids = self._fetch_existing_job_ids(job_ids)
        new_records = []
        new_mappings = []
        for job in api_data:
            job_id = str(job.get("id")) if job.get("id") is not None else None
            if not job_id or job_id in existing_ids:
                continue
            new_records.append((
                job_id,
                group_name,
                project_path,
                job.get("created_at"),
                job.get("finished_at"),
                job.get("status"),
            ))
            new_mappings.append(job)
        if new_records:
            self._insert_jobs(new_records)
            self.logger.info(f"Inserted {len(new_records)} new jobs for {group_name}/{project_path}")
        return new_mappings

    def _fetch_existing_job_ids(self, job_ids: list[str]) -> set[str]:
        assert self.cursor is not None
        placeholders = ",".join("?" for _ in job_ids)
        self.cursor.execute(
            f"SELECT job_id FROM {self.TABLE_NAME} WHERE job_id IN ({placeholders})",
            job_ids,
        )
        return {row[0] for row in self.cursor.fetchall()}

    def _insert_jobs(self, records: list[tuple]) -> None:
        assert self.cursor is not None
        self.cursor.executemany(
            f"""
            INSERT INTO {self.TABLE_NAME}
            (job_id, group_name, project_path, started, ended, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            records,
        )
