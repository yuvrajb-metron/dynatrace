"""SQLite job scan history."""

import sqlite3
from typing import Any, Iterable
from dynatrace_extension.sdk.extension import extension_logger as logger


class JobDatabase:
    TABLE_NAME = "job_history"

    def __init__(self, db_name: str = "jobs_scan_history.db"):
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
                org_name TEXT,
                repo_name TEXT,
                started TEXT,
                ended TEXT,
                status TEXT
            )
        """)

    def sync_success_jobs(
        self,
        api_data: list[dict[str, Any]] | None,
        org: str,
        repo: str,
    ) -> list[dict[str, Any]]:
        """
        Sync jobs into the database. Expects api_data to be already filtered
        (success + within first-time window). Returns a list of newly inserted job mappings.
        """
        if not isinstance(api_data, list):
            self.logger.warning("sync_success_jobs received invalid api_data; expected list.")
            return []
        if not api_data:
            self.logger.info("No jobs to sync for org '%s', repo '%s'.", org, repo)
            return []

        job_ids = self._extract_job_ids(api_data)
        if not job_ids:
            self.logger.info("No valid job IDs found for org '%s', repo '%s'.", org, repo)
            return []

        existing_ids = self._fetch_existing_job_ids(job_ids)
        new_records, new_mappings = self._prepare_new_jobs(
            api_data, existing_ids, org, repo
        )

        if not new_records:
            self.logger.info("No new successful jobs to insert for org '%s', repo '%s'.", org, repo)
            return []

        self._insert_jobs(new_records)
        self.logger.info(
            "Inserted %d new successful job(s) for org '%s', repo '%s'.",
            len(new_records),
            org,
            repo,
        )
        return new_mappings

    def _extract_job_ids(self, jobs: Iterable[dict[str, Any]]) -> list[str]:
        return [
            job_id
            for job in jobs
            if (job_id := job.get("jobId")) is not None
        ]

    def _fetch_existing_job_ids(self, job_ids: list[str]) -> set[str]:
        if not job_ids:
            return set()

        assert self.cursor is not None
        placeholders = ",".join("?" for _ in job_ids)

        self.cursor.execute(
            f"SELECT job_id FROM {self.TABLE_NAME} WHERE job_id IN ({placeholders})",
            job_ids,
        )
        return {row[0] for row in self.cursor.fetchall()}

    def _prepare_new_jobs(
        self,
        success_jobs: list[dict[str, Any]],
        existing_ids: set[str],
        org: str,
        repo: str,
    ) -> tuple[list[tuple], list[dict[str, Any]]]:
        new_records: list[tuple] = []
        new_mappings: list[dict[str, Any]] = []

        for job in success_jobs:
            job_id = job.get("jobId")
            if not job_id or job_id in existing_ids:
                continue

            new_records.append((
                job_id,
                org,
                repo,
                job.get("startedAt"),
                job.get("completedAt"),
                job.get("status"),
            ))

            new_mappings.append({
                "job_id": job_id,
                "org_name": org,
                "repo_name": repo,
                "started": job.get("startedAt"),
                "status": job.get("status"),
            })

        return new_records, new_mappings

    def _insert_jobs(self, records: list[tuple]) -> None:
        assert self.cursor is not None
        self.cursor.executemany(
            f"""
            INSERT INTO {self.TABLE_NAME}
            (job_id, org_name, repo_name, started, ended, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            records,
        )








