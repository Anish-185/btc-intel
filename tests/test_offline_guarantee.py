"""Nothing in this system reaches the network — asserted, not assumed.

`config.yaml` says `offline: true` and `offline/pipeline.py` asserts it, but an
assert only catches the code that reads the flag. This reads the source instead:
every Python file, every shell script, every line of the console. One
`requests.get` added in a hurry is all it takes to turn an air-gapped claim into
a false one, and the person who notices should not be a judge with the network
cable out.

Two scripts are *supposed* to use the network — they are the online half of the
offline install — and they are named here with the reason. Anything else that
starts reaching out has to come past this file first.

    python -m pytest tests/test_offline_guarantee.py -q
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: Never scanned: not ours, or not shipped.
SKIP_DIRS = {".venv", "venv", "vendor", "node_modules", ".git", "__pycache__",
             "dist", "build", ".pytest_cache", ".ruff_cache", "wheelhouse", "htmlcov"}

#: The online half of the offline install. Each of these downloads something
#: on a machine that has internet, so that the machine that does not, need not.
ONLINE_BY_DESIGN = {
    "offline/fetch_intel.sh":
        "fetches the Bitnodes/Tor/ASN snapshots into data/intel/, run once while online",
    "offline/build_wheelhouse.sh":
        "downloads the wheels, the intel snapshot and builds the console, run while online",
    "tests/test_offline_guarantee.py":
        "this file, which contains the patterns it searches for",
    "offline/airgap_check.sh":
        "probes pypi.org once to prove it is UNREACHABLE — the run means nothing if "
        "that probe succeeds; every other request it makes is to 127.0.0.1",
}

#: Python ways of opening a connection. Deliberately broad: a false positive
#: costs one line in ONLINE_BY_DESIGN, a false negative costs the claim.
PYTHON_NETWORK = re.compile(
    r"""\b(
        requests\.(get|post|put|delete|head|patch|Session)
      | urllib\.request
      | urlopen
      | httpx\.(get|post|put|delete|stream|Client|AsyncClient)
      | aiohttp\.
      | socket\.(socket|create_connection)
      | smtplib\. | ftplib\. | telnetlib\.
      | boto3\. | urllib3\.PoolManager
    )\b""",
    re.VERBOSE,
)

#: A URL that is not this machine talking to itself.
EXTERNAL_URL = re.compile(r"""https?://(?!(127\.0\.0\.1|localhost|0\.0\.0\.0|\$|\{))""")

#: Every browser call the console makes, and what it was given.
BROWSER_CALL = re.compile(r"""\b(fetch|EventSource|WebSocket|XMLHttpRequest)\s*\(\s*([^\n)]*)""")


def ours(suffixes: tuple[str, ...]) -> list[Path]:
    """Every file we wrote with one of these extensions."""
    out = []
    for path in ROOT.rglob("*"):
        if path.suffix not in suffixes or not path.is_file():
            continue
        if SKIP_DIRS & set(path.relative_to(ROOT).parts):
            continue
        out.append(path)
    return out


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def lines_matching(path: Path, pattern: re.Pattern) -> list[tuple[int, str]]:
    """Matching lines, minus comments — a URL in a comment documents a source,
    it does not contact one."""
    found = []
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue
        if pattern.search(line):
            found.append((n, stripped[:120]))
    return found


def test_no_python_module_opens_a_connection():
    """No HTTP client, socket, or mail/FTP library anywhere in our Python."""
    offenders = {
        rel(path): hits
        for path in ours((".py",))
        if rel(path) not in ONLINE_BY_DESIGN
        and (hits := lines_matching(path, PYTHON_NETWORK))
    }
    assert not offenders, (
        "these files reach the network — if that is deliberate, add the file to "
        f"ONLINE_BY_DESIGN with the reason:\n{_report(offenders)}"
    )


def test_no_python_module_names_an_external_url():
    """A URL in live code is a fetch waiting to happen."""
    offenders = {
        rel(path): hits
        for path in ours((".py",))
        if rel(path) not in ONLINE_BY_DESIGN
        and (hits := lines_matching(path, EXTERNAL_URL))
    }
    assert not offenders, (
        f"external URLs outside comments:\n{_report(offenders)}"
    )


def test_no_shell_script_downloads_from_somewhere_else():
    """The shell half of the same question.

    `curl` on its own is not the problem — the launcher and the checklist
    script talk to 127.0.0.1 constantly. What matters is a downloader pointed
    at a host that is not this machine, so both have to be on the line.
    """
    downloader = re.compile(r"\b(curl|wget)\b")
    offenders = {}
    for path in ours((".sh",)):
        if rel(path) in ONLINE_BY_DESIGN:
            continue
        hits = [(n, text) for n, text in lines_matching(path, downloader)
                if EXTERNAL_URL.search(text)]
        if hits:
            offenders[rel(path)] = hits
    assert not offenders, f"shell scripts that fetch from elsewhere:\n{_report(offenders)}"


def test_the_console_only_ever_calls_its_own_api():
    """Every fetch, EventSource and WebSocket goes through API_BASE.

    `API_BASE` is empty in the offline build, so the call is same-origin — the
    FastAPI process that served the page. A literal host in any of these would
    be a request to somewhere else.
    """
    offenders = {}
    for path in ours((".ts", ".tsx")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            for call, argument in BROWSER_CALL.findall(line):
                if EXTERNAL_URL.search(argument):
                    offenders.setdefault(rel(path), []).append((n, f"{call}({argument[:80]}"))
    assert not offenders, (
        f"the console calls something other than its own API:\n{_report(offenders)}"
    )


def test_the_page_shell_loads_nothing_from_a_cdn():
    """No <link> or <script> to a font service or a CDN in the HTML we write."""
    html = [ROOT / "web" / "index.html"]
    offenders = {}
    for path in html:
        if not path.exists():
            continue
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"""(src|href)\s*=\s*["']https?://""", line):
                offenders.setdefault(rel(path), []).append((n, line.strip()[:120]))
    assert not offenders, f"the page loads something remote:\n{_report(offenders)}"


@pytest.mark.skipif(not (ROOT / "web" / "dist").exists(),
                    reason="the console has not been built")
def test_the_built_console_contains_no_external_host():
    """The same check against what actually ships.

    Source can be clean while a dependency bakes in a CDN URL, so this reads
    the built bundle. Licence banners legitimately contain URLs as text; what
    matters is that none of them is being requested, so this looks for URLs
    next to something that fetches.
    """
    fetching = re.compile(
        r"""(fetch|EventSource|WebSocket|importScripts|\.src\s*=|\.href\s*=)"""
        r"""[^\n;]{0,80}https?://(?!(127\.0\.0\.1|localhost))""")
    offenders = {}
    for path in (ROOT / "web" / "dist").rglob("*"):
        if path.suffix not in (".js", ".css", ".html") or not path.is_file():
            continue
        text = path.read_text(errors="replace")
        for match in fetching.finditer(text):
            offenders.setdefault(rel(path), []).append(
                (text.count("\n", 0, match.start()) + 1, match.group(0)[:100]))
    assert not offenders, (
        "the built console would request something remote:\n" + _report(offenders)
    )


def test_config_says_offline():
    """The flag the pipeline asserts on, checked here too so a change to it
    fails in the suite rather than at the start of a demo."""
    import config
    assert config.load()["offline"] is True


def _report(offenders: dict[str, list[tuple[int, str]]]) -> str:
    return "\n".join(f"  {path}:{n}  {text}"
                     for path, hits in sorted(offenders.items()) for n, text in hits)
