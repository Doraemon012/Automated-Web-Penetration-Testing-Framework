import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional
from uuid import uuid4


class Reporter:
    """Memory-efficient collector that streams findings to disk."""

    def __init__(self, chunk_size: int = 50, buffer_dir: Optional[str] = None) -> None:
        self.chunk_size = max(1, chunk_size)
        self._buffer: List[Dict[str, Any]] = []
        base_dir = Path(buffer_dir) if buffer_dir else Path("reports") / ".buffers"
        base_dir.mkdir(parents=True, exist_ok=True)
        self._buffer_path = base_dir / f"findings_{uuid4().hex}.ndjson"
        self._buffer_path.touch()
        self._total = 0
        self._finalized = False

    # ------------------------------------------------------------------
    # Collection helpers
    # ------------------------------------------------------------------
    def add_findings(self, issues: Optional[Iterable[Dict[str, Any]]]) -> None:
        if not issues:
            return
        for issue in issues:
            self._buffer.append(issue)
            self._total += 1
            if len(self._buffer) >= self.chunk_size:
                self._flush_buffer()

    def _flush_buffer(self) -> None:
        if not self._buffer:
            return
        with open(self._buffer_path, "a", encoding="utf-8") as handle:
            for record in self._buffer:
                handle.write(json.dumps(record, ensure_ascii=False))
                handle.write("\n")
        self._buffer.clear()

    def finalize(self) -> None:
        if self._finalized:
            return
        self._flush_buffer()
        self._finalized = True

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------
    def iter_findings(self) -> Iterator[Dict[str, Any]]:
        self.finalize()
        with open(self._buffer_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)

    def overwrite(self, findings: Iterable[Dict[str, Any]]) -> None:
        """Replace buffered findings with a new iterable, streaming to disk."""
        temp_path = self._buffer_path.with_name(f"processed_{uuid4().hex}.ndjson")
        count = 0
        with open(temp_path, "w", encoding="utf-8") as handle:
            for finding in findings:
                handle.write(json.dumps(finding, ensure_ascii=False))
                handle.write("\n")
                count += 1
        temp_path.replace(self._buffer_path)
        self._buffer.clear()
        self._total = count
        self._finalized = True

    @property
    def total_findings(self) -> int:
        return self._total

    # ------------------------------------------------------------------
    # Report writers
    # ------------------------------------------------------------------
    def _iter_source(self, findings: Optional[Iterable[Dict[str, Any]]]) -> Iterator[Dict[str, Any]]:
        if findings is None:
            yield from self.iter_findings()
        else:
            for item in findings:
                yield item

    def save_json(self, filename: str = "report.json", findings: Optional[Iterable[Dict[str, Any]]] = None) -> None:
        iterator = self._iter_source(findings)
        with open(filename, "w", encoding="utf-8") as handle:
            handle.write("[\n")
            first = True
            for issue in iterator:
                if not first:
                    handle.write(",\n")
                serialized = json.dumps(issue, ensure_ascii=False, indent=4)
                indented = "\n".join(f"    {line}" for line in serialized.splitlines())
                handle.write(indented)
                first = False
            handle.write("\n]\n")
        print(f"[+] JSON report saved: {filename}")

    def save_markdown(self, filename: str = "report.md", findings: Optional[Iterable[Dict[str, Any]]] = None) -> None:
        iterator = self._iter_source(findings)
        with open(filename, "w", encoding="utf-8") as handle:
            handle.write("# 🛡 Vulnerability Report\n\n")
            for issue in iterator:
                handle.write(f"## {issue.get('vulnerability', 'Unknown Vulnerability')}\n")
                handle.write(f"- **URL:** {issue.get('url', 'N/A')}\n")
                payload = issue.get("payload")
                if payload:
                    handle.write(f"- **Payload:** `{payload}`\n")
                handle.write(f"- **Severity:** {issue.get('severity', 'Unknown')}\n")
                description = issue.get('description', 'No description provided.')
                handle.write(f"- **Description:** {description}\n\n")
        print(f"[+] Markdown report saved: {filename}")

    # ------------------------------------------------------------------
    def cleanup(self) -> None:
        try:
            self._buffer_path.unlink(missing_ok=True)
        except OSError:
            pass
