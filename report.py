import json
import sys
from datetime import date

ORDER = ["Critical", "High", "Medium", "Low"]


def build_report(findings, app_name, model_name):
    findings = sorted(
        findings,
        key=lambda f: ORDER.index(f["severity"]) if f.get("severity") in ORDER else 99,
    )
    counts = {s: 0 for s in ORDER}
    for f in findings:
        if f.get("severity") in counts:
            counts[f["severity"]] += 1

    out = []
    out.append("# Security Assessment Report\n")
    out.append("## 1. Assessment Information\n")
    out.append(f"**Application:** {app_name}\n")
    out.append("**Assessment Type:** AI-Assisted Static Code Review\n")
    out.append(f"**Assessment Date:** {date.today().isoformat()}\n")
    out.append(f"**AI Model:** {model_name}\n")

    out.append("## 2. Executive Summary\n")
    out.append(
        f"The source code was analyzed to identify potential security weaknesses. "
        f"The review produced **{len(findings)} findings** "
        f"({counts['Critical']} Critical, {counts['High']} High, "
        f"{counts['Medium']} Medium, {counts['Low']} Low). "
        "Each finding was checked automatically to confirm that the quoted code "
        "exists in the reported file. AI-assisted findings should still be "
        "validated by a developer before being treated as confirmed vulnerabilities.\n"
    )

    out.append("## 3. Findings Summary\n")
    out.append("| Severity | Count |\n|---|---:|")
    for s in ORDER:
        out.append(f"| {s} | {counts[s]} |")
    out.append(f"| **Total** | **{len(findings)}** |\n")

    out.append("| ID | Severity | File | Title |\n|---|---|---|---|")
    for i, f in enumerate(findings, 1):
        out.append(f"| TF-{i:03d} | {f['severity']} | `{f['file']}` | {f['title']} |")
    out.append("")

    out.append("## 4. Detailed Findings\n")
    for i, f in enumerate(findings, 1):
        out.append(f"### Finding TF-{i:03d}: {f['title']}\n")
        out.append(f"**Severity:** {f['severity']}  ")
        out.append(f"**Category:** {f.get('category', '')}  ")
        out.append(f"**CWE:** {f.get('cwe', '')}  ")
        out.append(f"**Confidence:** {f.get('confidence', '')}  ")
        out.append(f"**Affected File:** `{f['file']}`  ")
        out.append(f"**Code Location:** lines {f.get('line_start')}-{f.get('line_end')}\n")
        out.append(f"#### Description\n\n{f.get('description', '')}\n")
        out.append(f"#### Vulnerable Code\n\n```\n{f.get('evidence', '')}\n```\n")
        out.append(f"#### Potential Impact\n\n{f.get('impact', '')}\n")
        out.append(f"#### Recommended Fix\n\n{f.get('fix', '')}\n")
        out.append(f"#### Secure Code Example\n\n```\n{f.get('secure_code', '')}\n```\n")
        out.append(f"#### Assumptions and Validation Notes\n\n{f.get('assumptions', '')}\n")

    out.append("## 5. Overall Assessment\n")
    if counts["Critical"] or counts["High"]:
        out.append(
            "The application shows significant potential weaknesses in access control "
            "and input handling. Address the Critical and High findings first, then "
            "work through the Medium and Low items.\n"
        )
    elif findings:
        out.append("Only lower-severity issues were identified. Review and prioritize them.\n")
    else:
        out.append("No issues were identified in the reviewed files. This does not guarantee the code is secure.\n")

    out.append("## 6. Scope and Limitations\n")
    out.append("- Static code review only; no exploit execution or runtime testing")
    out.append("- AI output can be incomplete or wrong, so some findings need manual confirmation")
    out.append("- No guarantee that every vulnerability was found")
    out.append("- Impact statements assume the endpoint can be reached by the stated caller. Whether a login is required before an edge function runs (platform or gateway settings) is not visible in the code")
    out.append("- Exploitability depends on deployment context that is not visible in the code\n")
    return "\n".join(out)


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "verified_findings.json"
    app = sys.argv[2] if len(sys.argv) > 2 else "CDF TaskFlow"
    findings = json.load(open(src))
    with open("security_report.md", "w") as f:
        f.write(build_report(findings, app, "gemini-3.5-flash-lite"))
    print(f"Wrote security_report.md with {len(findings)} findings")
