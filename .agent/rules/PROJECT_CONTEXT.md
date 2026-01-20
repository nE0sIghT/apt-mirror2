# PROJECT_CONTEXT.md - apt-mirror2 Context

## Project Overview
`apt-mirror2` is a robust, Python/asyncio reimplementation of the classic `apt-mirror` tool. It is designed to create local mirrors of Debian/Ubuntu repositories.
- **Goal**: Drop-in replacement for `apt-mirror` with improved reliability, speed (asyncio), and correctness.
- **Key Differentiator**: Ensures mirror consistency by validating data integrity at all stages. Never leaves a broken mirror if it exits successfully.
- **License**: GPL-3.0-or-later.

## Architecture
The system is built around an asynchronous event loop driving concurrent downloads and validation.

### Core Components
1.  **`APTMirror` (`apt_mirror/apt_mirror.py`)**:
    -   Entry point.
    -   Parses configuration (`Config`).
    -   Orchestrates concurrent `RepositoryMirror` tasks.
    -   Manages global resources (semaphores, rate limiters, Prometheus metrics).

2.  **`RepositoryMirror` (`apt_mirror/apt_mirror.py`)**:
    -   Manages the mirroring lifecycle for a single repository.
    -   Steps:
        1.  Download Release files (signed).
        2.  Download Metadata (Packages, Sources, etc.).
        3.  Clean/Prepare "skel" directory (staging area).
        4.  Download Pool files (packages).
        5.  Atomic move of metadata (dists folder) to final mirror path.
        6.  Cleanup (garbage collection).

3.  **`Downloader` (`apt_mirror/download/`)**:
    -   Handles HTTP/HTTPS/FTP.
    -   Validates file size and checksums (MD5, SHA1, SHA256, SHA512) on the fly.
    -   Supports resuming downloads.
    -   Uses `httpx` (supports HTTP/2).

4.  **`Config` (`apt_mirror/config.py`)**:
    -   Parses `mirror.list` (legacy) and `*.sources` (deb822).
    -   Supports variable substitution and extensive per-repository configuration.

### Data Flow
`Source` -> `Release Files` -> `Metadata (Indices)` -> `Pool Files (Debs)` -> `Atomic Update`

## Codebase Map
-   `apt_mirror/`: Source package.
    -   `apt_mirror.py`: Main logic.
    -   `config.py`: Configuration models.
    -   `repository.py`: Repository metadata parsing (`SourcesParser`, `PackagesParser`).
    -   `download/`: Downloader logic (`downloader.py`, `item.py`).
-   `tests/`: `pytest` test suite.
-   `pyproject.toml`: Build and dependency configuration.

## Development Ecosystem
-   **Language**: Python 3.10+
-   **Dependencies**:
    -   `aiofile`: Async file I/O.
    -   `aiolimiter`: Rate limiting.
    -   `httpx[http2]`: Async HTTP client.
    -   `python-debian`: Deb822 and GPG handling.
    -   `uvloop`: (Optional) faster event loop.
-   **Testing**: `pytest`
-   **Linting**: `ruff`, `pylint`

## Conventions
-   **Async First**: All I/O should be asynchronous.
-   **Type Hinting**: Use modern Python type hints (`list[str]`, `str | None`).
-   **Error Handling**: Fail safe. Validation errors in mirroring should prevent the atomic update of the `dists` directory to avoid exposing a broken state.
-   **Logging**: Structured logging via `LoggerFactory`.

## Usage
Running the mirror:
```bash
python3 -m apt_mirror.apt_mirror /path/to/config.list
```

Running tests:
```bash
pytest
```
