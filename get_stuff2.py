from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, Iterable
import sys
import json
import urllib.request
import urllib.error
import platform
from datetime import datetime

# ---------- Domain model ----------
@dataclass
class PageInfo:
    title: str
    length: int
    source: str = "bbc"
    cached: bool = False

    def __post_init__(self):
        if not isinstance(self.title, str) or not self.title:
            raise ValueError("title must be a non-empty string")
        if not isinstance(self.length, int) or self.length < 0:
            raise ValueError("length must be a non-negative integer")

# ---------- Transport ----------
def http_get(url: str, timeout: int = 5) -> Optional[str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status < 200 or resp.status >= 300:
                return None
            raw = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
            return raw.decode(charset, errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
        return None

def fetch() -> Optional[PageInfo]:
    html = http_get("https://www.bbc.co.uk/")
    if html is None:
        return None
    return PageInfo(title="BBC Homepage", length=len(html))

# ---------- Simple ASCII table ----------
def ascii_table(title: str, rows: Dict[str, str]) -> str:
    key_w = max(len(k) for k in rows.keys()) if rows else 5
    val_w = max(len(str(v)) for v in rows.values()) if rows else 5
    w = key_w + val_w + 7
    line = "+" + "-" * (w - 2) + "+"
    out = [line, f"| {title.center(w-4)} |", line]
    for k, v in rows.items():
        out.append(f"| {k.ljust(key_w)} | {str(v).ljust(val_w)} |")
    out.append(line)
    return "\n".join(out)

# ---------- Dependency report ----------
CURATED_STD_DEPS = {
    # networking and protocols
    "urllib", "http", "ssl", "socket",
    # header parsing and email-style MIME
    "email",
    # codecs and encodings path
    "encodings", "codecs",
    # model and serialisation layers
    "dataclasses", "json",
    # time utils sometimes pulled by stdlib
    "time", "datetime",
}

def normalise_modules(modnames: Iterable[str]) -> set[str]:
    # Keep only top level package names
    return {name.split(".")[0] for name in modnames}

def dependency_report(pre: set[str], post: set[str]) -> Dict[str, str]:
    added = normalise_modules(post - pre)
    used = added.intersection(CURATED_STD_DEPS)
    # Map to simple roles for teaching
    roles = []
    if "urllib" in used:
        roles.append("Transport: urllib.request for HTTP")
    if "ssl" in used or "socket" in used:
        roles.append("TLS and sockets: ssl or socket used under the hood")
    if "email" in used:
        roles.append("Header parsing: email package for HTTP-style headers")
    if "encodings" in used or "codecs" in used:
        roles.append("Decoding: encodings and codecs for text decode")
    if "dataclasses" in used:
        roles.append("Model: dataclasses for PageInfo")
    if "json" in used:
        roles.append("Serialisation: json for structured output")

    info = {
        "python": platform.python_version(),
        "time": datetime.utcnow().isoformat() + "Z",
        "modules_used": ", ".join(sorted(used)) if used else "(no curated entries detected)",
        "roles": " | ".join(roles) if roles else "Standard library only; roles inferred as transport, decode, model",
    }
    return info


if __name__ == "__main__":
    # Snapshot modules before network call
    pre = set(sys.modules.keys())

    info = fetch()

    # Snapshot after network call
    post = set(sys.modules.keys())
    report = dependency_report(pre, post)

    # Primary table
    if info:
        rows = {
            "title": info.title,
            "length": str(info.length),
            "source": info.source,
            "cached": str(info.cached),
        }
    else:
        rows = {"error": "fetch failed"}

    print(ascii_table("Demo: nested and chained dependencies", rows))

    # JSON summary for those who prefer structured output
    summary = {
        "result": rows,
        "dependency_report": report,
    }
    print("\nJSON summary:")
    print(json.dumps(summary, indent=2))

    # Human readable dependency report
    print("\nDependency report:")
    dep_rows = {
        "python": report["python"],
        "modules_used": report["modules_used"],
        "roles": report["roles"],
        "generated_at": report["time"],
    }
    print(ascii_table("Observed dependencies and roles", dep_rows))
