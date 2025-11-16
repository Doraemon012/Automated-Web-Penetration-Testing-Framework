from typing import Any, Dict, Iterable, Iterator

from reports.cvss_compute import enhance_finding_with_cvss, deduplicate_findings
from reports.risk import enrich_findings


def finalize_findings(findings: Iterable[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    """Apply CVSS, deduplication, and enrichment with minimal buffering."""
    enhanced_iter = (enhance_finding_with_cvss(dict(finding)) for finding in findings)
    deduped = deduplicate_findings(enhanced_iter)
    return enrich_findings(deduped)
