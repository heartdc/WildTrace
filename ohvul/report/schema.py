from __future__ import annotations
from datetime import datetime, timezone
from ohvul.domain.evidence import digest

def build_audit_report(scan_result: dict) -> dict:
    findings=[]
    for item in scan_result.get("findings",[]): findings.append({"alert_id":item["alert_id"],"status":"candidate","cwe":item.get("cwe_candidate"),"rule":item.get("rule"),"location":item.get("location"),"evidence_id":item.get("evidence_id")})
    return {"report_schema":"0.2","report_kind":"defensive_code_audit","generated_at":datetime.now(timezone.utc).isoformat(),"scan_result_sha256":digest(scan_result),"assessment":{"status":"candidate_only","confirmed_vulnerabilities":0,"note":"Static candidates require separate verification and human review."},"workflow":scan_result.get("workflow"),"findings":findings,"evidence_refs":[b["evidence_id"] for b in scan_result.get("evidence_bundles",[])],"safety":{"local_only":True,"no_execution":True,"no_network":True,"no_external_submission":True}}

def validate_audit_report(report: dict) -> None:
    required={"report_schema","report_kind","generated_at","scan_result_sha256","assessment","workflow","findings","evidence_refs","safety"}
    if not isinstance(report,dict) or set(report)!=required or report["report_schema"]!="0.2": raise ValueError("invalid report schema")
    if not isinstance(report["scan_result_sha256"],str) or len(report["scan_result_sha256"])!=64: raise ValueError("invalid scan result digest")
    if report["assessment"].get("status")!="candidate_only" or report["assessment"].get("confirmed_vulnerabilities")!=0: raise ValueError("report cannot claim confirmed vulnerability")
    if report["safety"]!={"local_only":True,"no_execution":True,"no_network":True,"no_external_submission":True}: raise ValueError("invalid safety boundary")
    refs=set(report["evidence_refs"])
    for item in report["findings"]:
        if item.get("status")!="candidate" or item.get("evidence_id") not in refs: raise ValueError("finding must be candidate with evidence reference")

def validate_report_against_result(report: dict, scan_result: dict) -> None:
    validate_audit_report(report)
    if report["scan_result_sha256"] != digest(scan_result): raise ValueError("report does not match scan result")
    expected = {item["alert_id"]: (item.get("evidence_id"), item.get("cwe_candidate"), item.get("rule"), item.get("location")) for item in scan_result.get("findings", [])}
    actual = {item.get("alert_id"): (item.get("evidence_id"), item.get("cwe"), item.get("rule"), item.get("location")) for item in report.get("findings", [])}
    if actual != expected: raise ValueError("report findings do not match scan findings")
    expected_refs = {item["evidence_id"] for item in scan_result.get("evidence_bundles", [])}
    if set(report.get("evidence_refs", [])) != expected_refs: raise ValueError("report evidence references do not match scan")
