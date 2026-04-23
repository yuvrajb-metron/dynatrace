"""
Run Docker login and Docker Scout CVES/SBOM via subprocess.

Image ref format: org/repo:tag; commands use registry://<org>/<repo>:<tag>.
Timeouts: login 30s, cves/sbom 600s by default.

"""
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Optional

from appsec_dockerscout.models import ImageRef
from dynatrace_extension import StatusValue
from dynatrace_extension.sdk.extension import extension_logger as logger

DEFAULT_CVES_TIMEOUT = 600
DEFAULT_SBOM_TIMEOUT = 600
DEFAULT_LOGIN_TIMEOUT = 30


def _set_home_to_dtuserag() -> str:
    """
    Set HOME dynamically using pathlib (current user's home).

    Returns:
        The HOME value after assignment.
    """
    previous_home = os.environ.get("HOME", "")
    logger.debug("Setting HOME for docker commands. Previous HOME=%s", previous_home)
    detected_home = "/home/dtuserag"
    os.environ["HOME"] = detected_home

    logger.debug("HOME set to: %s", os.environ["HOME"])
    return os.environ["HOME"]

@dataclass
class ScoutResult:
    """Output of a scout command (stdout, stderr, returncode)."""

    stdout: str
    stderr: str
    returncode: int
    success: bool


def _completed_process_to_scout_result(proc: subprocess.CompletedProcess) -> ScoutResult:
    """
    Normalize ``subprocess.run`` output into a ``ScoutResult``.

    Handles both modes used by this module: ``text=True`` (stdout/stderr are ``str``)
    and ``text=False`` (bytes are decoded as UTF-8 with replacement for invalid
    sequences, matching prior login behavior).

    Args:
        proc: Completed process from ``subprocess.run`` with ``capture_output=True``.

    Returns:
        ``ScoutResult`` with string stdout/stderr, ``returncode`` (0 if the process
        returned ``None``), and ``success`` True only when ``returncode == 0``.
    """
    out, err = proc.stdout, proc.stderr
    if isinstance(out, bytes):
        stdout = out.decode("utf-8", errors="replace") if out else ""
    else:
        stdout = out or ""
    if isinstance(err, bytes):
        stderr = err.decode("utf-8", errors="replace") if err else ""
    else:
        stderr = err or ""
    return ScoutResult(
        stdout=stdout,
        stderr=stderr,
        returncode=proc.returncode or 0,
        success=proc.returncode == 0,
    )


def _run_docker_subprocess(
    cmd: list[str],
    *,
    timeout: int,
    text: bool,
    input_bytes: Optional[bytes] = None,
    timeout_warning: str,
    not_found_log: str,
    not_found_stderr: str,
    log_generic_exception: Callable[[Exception], None],
) -> ScoutResult:
    """
    Run a Docker CLI command with the extension's HOME layout and uniform error paths.

    Sets ``HOME`` via ``_set_home_to_dtuserag`` before each run so the Docker client
    config matches the Dynatrace extension user. Maps timeouts, missing ``docker``
    binary, and unexpected exceptions to the same ``ScoutResult`` shapes as the
    original per-command implementations.

    Args:
        cmd: Argument list passed to ``subprocess.run`` (executable first).
        timeout: Per-invocation timeout in seconds.
        text: If True, decode streams as text; if False, read bytes and decode in
            ``_completed_process_to_scout_result``.
        input_bytes: Optional stdin payload (e.g. password for ``docker login``);
            when set, typically used with ``text=False``.
        timeout_warning: Message for ``logger.warning`` on ``TimeoutExpired``.
        not_found_log: Message for ``logger.warning`` when the docker executable
            is not found.
        not_found_stderr: ``stderr`` string stored in the returned ``ScoutResult``
            for that case.
        log_generic_exception: Callback invoked to log any other ``Exception``
            before returning a failure result.

    Returns:
        ``ScoutResult`` from the completed process, or a synthetic failure result
        (empty stdout, ``returncode`` -1, ``success`` False) when the subprocess
        does not complete normally.
    """
    _set_home_to_dtuserag()
    try:
        run_kw: dict[str, Any] = {
            "capture_output": True,
            "timeout": timeout,
            "text": text,
        }
        if input_bytes is not None:
            run_kw["input"] = input_bytes
        proc = subprocess.run(cmd, **run_kw)
        return _completed_process_to_scout_result(proc)
    except subprocess.TimeoutExpired:
        logger.warning(timeout_warning)
        return ScoutResult(stdout="", stderr="timeout", returncode=-1, success=False)
    except FileNotFoundError:
        logger.warning(not_found_log)
        return ScoutResult(
            stdout="", stderr=not_found_stderr, returncode=-1, success=False
        )
    except Exception as e:
        log_generic_exception(e)
        return ScoutResult(stdout="", stderr=str(e), returncode=-1, success=False)


def _log_scout_nonzero_exit(
    scout_subcommand: str,
    uri: str,
    result: ScoutResult,
    multi_status: Optional[Any] = None,
) -> None:
    """
    Emit a warning when ``docker scout`` returned a non-zero exit code.

    Used after ``_run_docker_subprocess`` returns for ``cves``/``sbom`` so operators
    see return code and a truncated stderr (first 4000 characters) without repeating
    the same log formatting in two call sites. Optionally records the same summary on
    ``multi_status`` for the extension UI.

    Args:
        scout_subcommand: Scout subcommand name for the log line (e.g. ``cves`` or
            ``sbom``).
        uri: Registry URI passed to the scout command (for correlation in logs).
        result: Outcome of the scout run; ``stderr`` and ``returncode`` are logged.
        multi_status: Optional extension ``MultiStatus`` for operator-visible status.

    Returns:
        None.
    """
    err = (result.stderr or "").strip() or "(empty)"
    logger.warning(
        "docker scout %s failed for %s: returncode=%s stderr=%s",
        scout_subcommand,
        uri,
        result.returncode,
        err[:4000],
    )
    logger.warn("DEC:1F4 Docker Scout CVE or SBOM scan incomplete issue");
    if multi_status is not None:
        detail = err[:400] + ("…" if len(err) > 400 else "")
        multi_status.add_status(
            StatusValue.GENERIC_ERROR,
            f"DEC:1F4 Docker Scout {scout_subcommand} exited with code {result.returncode} "
            f"for {uri}. stderr (truncated): {detail}",
        )


def docker_login(
    username: str, password: str, timeout: int = DEFAULT_LOGIN_TIMEOUT
) -> ScoutResult:
    """
    Run docker login -u <username> --password-stdin with PAT on stdin.
    """
    logger.debug("docker login starting for user: %s", username)
    result = _run_docker_subprocess(
        ["docker", "login", "-u", username, "--password-stdin"],
        timeout=timeout,
        text=False,
        input_bytes=password.encode("utf-8"),
        timeout_warning="docker login timed out",
        not_found_log="docker not found",
        not_found_stderr="docker not found",
        log_generic_exception=lambda e: logger.warning("docker login failed: %s", e),
    )
    logger.debug(
        "docker login finished: success=%s, returncode=%s",
        result.success,
        result.returncode,
    )
    return result


def docker_scout_cves(
    image_ref: ImageRef,
    timeout: int = DEFAULT_CVES_TIMEOUT,
    multi_status: Optional[Any] = None,
) -> ScoutResult:
    """
    Run: docker scout cves --format sarif registry://<org>/<repo>:<tag>.

    Args:
        image_ref: Image to scan.
        timeout: Subprocess timeout in seconds.
        multi_status: If set, non-zero exits are also reported on extension status.
    """
    uri = image_ref.registry_uri()
    logger.debug("docker scout cves starting for uri: %s", uri)
    result = _run_docker_subprocess(
        ["docker", "scout", "cves", "--format", "sarif", uri],
        timeout=timeout,
        text=True,
        timeout_warning=f"docker scout cves timed out for {uri}",
        not_found_log="docker or docker scout not found",
        not_found_stderr="docker scout not found",
        log_generic_exception=lambda e: logger.warning(
            "docker scout cves failed for %s: %s", uri, e
        ),
    )
    logger.debug(
        "docker scout cves finished for %s: success=%s, stdout_len=%s",
        uri,
        result.success,
        len(result.stdout),
    )
    if not result.success:
        _log_scout_nonzero_exit("cves", uri, result, multi_status)
    return result


def docker_scout_sbom(
    image_ref: ImageRef,
    timeout: int = DEFAULT_SBOM_TIMEOUT,
    multi_status: Optional[Any] = None,
) -> ScoutResult:
    """
    Run: docker scout sbom --format json registry://<org>/<repo>:<tag>.

    Args:
        image_ref: Image to scan.
        timeout: Subprocess timeout in seconds.
        multi_status: If set, non-zero exits are also reported on extension status.
    """
    uri = image_ref.registry_uri()
    logger.debug("docker scout sbom starting for uri: %s", uri)
    result = _run_docker_subprocess(
        ["docker", "scout", "sbom", "--format", "json", uri],
        timeout=timeout,
        text=True,
        timeout_warning=f"docker scout sbom timed out for {uri}",
        not_found_log="docker or docker scout not found",
        not_found_stderr="docker scout not found",
        log_generic_exception=lambda e: logger.warning(
            "docker scout sbom failed for %s: %s", uri, e
        ),
    )
    logger.debug(
        "docker scout sbom finished for %s: success=%s, stdout_len=%s",
        uri,
        result.success,
        len(result.stdout),
    )
    if not result.success:
        _log_scout_nonzero_exit("sbom", uri, result, multi_status)
    return result
