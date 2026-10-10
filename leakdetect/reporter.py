"""
Reporter Module for Sensitive Data Leak Detector (T1-PS7).
Generates comprehensive reports in Markdown, HTML (with charts), JSON, CSV, and Console.
Complies with SRS Sections 7.1, 7.2, and FR-7.1 to FR-7.6.
"""

from __future__ import annotations
import csv
import datetime
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .detector import Finding
from .classifier import calculate_overall_risk, Severity
from .advisor import summarize_top_recommendations


class LeakReporter:
    """Compiles and exports scan findings across formats (JSON, CSV, MD, HTML, Console)."""

    def __init__(
        self,
        findings: List[Finding],
        files_scanned: List[str],
        rule_set_name: str = "default_rules.yaml",
        scan_time: Optional[datetime.datetime] = None,
    ):
        self.findings = findings
        self.files_scanned = files_scanned
        self.rule_set_name = rule_set_name
        self.scan_time = scan_time or datetime.datetime.now(datetime.timezone.utc)

        # Convert findings to dictionaries for metrics
        self.finding_dicts = [f.to_dict() for f in findings]
        self.risk_assessment = calculate_overall_risk(self.finding_dicts)
        self.top_recommendations = summarize_top_recommendations(self.finding_dicts)

        # Count by type
        self.type_counts: Dict[str, int] = {}
        for f in findings:
            self.type_counts[f.type] = self.type_counts.get(f.type, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        """Produces full structured dictionary representation."""
        return {
            "meta": {
                "tool": "Sensitive Data Leak Detector for APIs",
                "version": "1.0.0",
                "scan_time": self.scan_time.isoformat(),
                "rule_set": self.rule_set_name,
                "disclaimer": "NOTE: Findings are automated indicators of potential sensitive data leaks and require human security review (FR-7.6).",
            },
            "summary": {
                "total_files_scanned": len(self.files_scanned),
                "files": self.files_scanned,
                "total_findings": len(self.findings),
                "overall_risk_level": self.risk_assessment["level"],
                "risk_score": self.risk_assessment["score"],
                "risk_summary": self.risk_assessment["summary"],
                "severity_counts": self.risk_assessment["counts"],
                "type_counts": self.type_counts,
            },
            "top_recommendations": self.top_recommendations,
            "findings": self.finding_dicts,
        }

    def to_json(self, indent: int = 2) -> str:
        """Exports report in JSON format (FR-7.4)."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_csv(self) -> str:
        """Exports report in CSV format (FR-7.4)."""
        output = io.StringIO()
        fieldnames = [
            "finding_id",
            "file",
            "location",
            "rule_id",
            "rule_name",
            "type",
            "severity",
            "confidence",
            "masked_value",
            "risk",
            "recommendation",
            "standards",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for f in self.finding_dicts:
            row = dict(f)
            row["standards"] = "; ".join(row.get("standards", []))
            writer.writerow(row)

        return output.getvalue()

    def to_markdown(self) -> str:
        """Exports report in clean Markdown format (FR-7.4)."""
        meta = self.to_dict()["meta"]
        summary = self.to_dict()["summary"]

        md = []
        md.append("# 🛡️ Sensitive Data Leak Detector for APIs — Scan Report\n")
        md.append(f"**Scan Date/Time**: `{meta['scan_time']}`  ")
        md.append(f"**Tool Version**: `{meta['version']}`  ")
        md.append(f"**Rule Set**: `{meta['rule_set']}`  ")
        md.append(f"**Files Scanned**: {summary['total_files_scanned']}  \n")

        md.append("## Executive Summary\n")
        md.append(f"- **Overall Risk Level**: **`{summary['overall_risk_level']}`** (Risk Score: {summary['risk_score']}/100)")
        md.append(f"- **Total Sensitive Findings**: `{summary['total_findings']}`")
        md.append(f"- **Status Note**: {summary['risk_summary']}\n")

        md.append("### Findings by Severity")
        md.append("| Severity | Count |")
        md.append("| :--- | :--- |")
        for sev, count in summary["severity_counts"].items():
            badge = "🔴" if sev == "Critical" else "🟠" if sev == "High" else "🟡" if sev == "Medium" else "🔵"
            md.append(f"| {badge} {sev} | {count} |")
        md.append("")

        md.append("### Findings by Type")
        md.append("| Category | Count |")
        md.append("| :--- | :--- |")
        for ftype, count in summary["type_counts"].items():
            md.append(f"| 🏷️ {ftype} | {count} |")
        md.append("")

        if self.top_recommendations:
            md.append("## Top Remediation Recommendations\n")
            for i, rec in enumerate(self.top_recommendations, 1):
                md.append(f"{i}. **[{rec['priority']}] {rec['title']}**")
                md.append(f"   - **Remediation**: {rec['recommendation']}")
                md.append(f"   - **Risk**: {rec['risk']}\n")

        md.append("## Detailed Findings Table\n")
        if not self.findings:
            md.append("✅ *No sensitive data leaks detected in scanned payload(s).*\n")
        else:
            md.append("| ID | Location | Type | Severity | Masked Value | Suggested Fix |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for f in self.findings:
                md.append(
                    f"| `{f.finding_id}` | `{f.location}` | {f.type} | **{f.severity}** | `{f.masked_value}` | {f.recommendation} |"
                )
            md.append("")

        md.append("> **Disclaimer**: *Findings are automated detections of potential sensitive data exposure and require human verification before making API code changes.*")

        return "\n".join(md)

    def to_html(self) -> str:
        """Exports report in modern responsive HTML format with interactive charts (FR-7.4, FR-7.5)."""
        data = self.to_dict()
        summary = data["summary"]
        findings_json = json.dumps(self.finding_dicts)
        sev_labels = list(summary["severity_counts"].keys())
        sev_values = list(summary["severity_counts"].values())
        type_labels = list(summary["type_counts"].keys())
        type_values = list(summary["type_counts"].values())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Sensitive Data Leak Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --clean: #10b981;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 30px 20px;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    .title {{
      font-size: 24px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .meta-tag {{
      color: var(--text-muted);
      font-size: 13px;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .kpi-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
      text-align: center;
    }}
    .kpi-title {{
      font-size: 13px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .kpi-val {{
      font-size: 32px;
      font-weight: 700;
      margin: 10px 0;
    }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
    }}
    .badge-Critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
    .badge-High {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
    .badge-Medium {{ background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }}
    .badge-Low {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }}
    .charts-container {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 30px;
    }}
    .chart-box {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border-radius: 10px;
      overflow: hidden;
      border: 1px solid var(--border);
    }}
    th, td {{
      padding: 12px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
    }}
    th {{
      background: rgba(15, 23, 42, 0.6);
      color: var(--text-muted);
      text-transform: uppercase;
      font-size: 11px;
    }}
    .code-pill {{
      font-family: monospace;
      background: rgba(255, 255, 255, 0.08);
      padding: 2px 6px;
      border-radius: 4px;
      color: #38bdf8;
    }}
    .disclaimer {{
      margin-top: 30px;
      padding: 15px;
      border-left: 4px solid #3b82f6;
      background: rgba(59, 130, 246, 0.1);
      border-radius: 4px;
      font-size: 13px;
      color: var(--text-muted);
    }}
    @media (max-width: 768px) {{
      .charts-container {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="title">🛡️ API Sensitive Data Leak Report</div>
        <div class="meta-tag">Generated: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')} | Tool: Sensitive Data Leak Detector v1.0.0</div>
      </div>
      <div>
        <span class="badge badge-{summary['overall_risk_level']}">{summary['overall_risk_level'].upper()} RISK</span>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-title">Overall Risk Score</div>
        <div class="kpi-val" style="color: {'#ef4444' if summary['risk_score'] >= 50 else '#10b981'}">{summary['risk_score']} / 100</div>
        <div class="meta-tag">{summary['risk_summary']}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Total Findings</div>
        <div class="kpi-val">{summary['total_findings']}</div>
        <div class="meta-tag">Across {summary['total_files_scanned']} file(s)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Critical & High</div>
        <div class="kpi-val" style="color: #ef4444">{summary['severity_counts'].get('Critical', 0) + summary['severity_counts'].get('High', 0)}</div>
        <div class="meta-tag">Requires Immediate Rotation / Fix</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Medium & Low</div>
        <div class="kpi-val" style="color: #eab308">{summary['severity_counts'].get('Medium', 0) + summary['severity_counts'].get('Low', 0)}</div>
        <div class="meta-tag">PII & Internal Topology Leaks</div>
      </div>
    </div>

    <div class="charts-container">
      <div class="chart-box">
        <h4 style="margin-top:0;">Findings by Severity</h4>
        <canvas id="sevChart" height="200"></canvas>
      </div>
      <div class="chart-box">
        <h4 style="margin-top:0;">Findings by Category</h4>
        <canvas id="typeChart" height="200"></canvas>
      </div>
    </div>

    <h3>Detailed Security Findings</h3>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Location</th>
          <th>Rule</th>
          <th>Category</th>
          <th>Severity</th>
          <th>Masked Value</th>
          <th>Suggested Fix</th>
        </tr>
      </thead>
      <tbody>
        {"".join([f'''<tr>
          <td><span class="code-pill">{f.finding_id}</span></td>
          <td><span class="code-pill">{f.location}</span></td>
          <td>{f.rule_name}</td>
          <td>{f.type}</td>
          <td><span class="badge badge-{f.severity}">{f.severity}</span></td>
          <td><span class="code-pill">{f.masked_value}</span></td>
          <td>{f.recommendation}</td>
        </tr>''' for f in self.findings]) if self.findings else '<tr><td colspan="7" style="text-align:center;">✅ No leaks identified in scanned payloads.</td></tr>'}
      </tbody>
    </table>

    <div class="disclaimer">
      <strong>Notice (FR-7.6):</strong> All findings generated are automated detections of potential sensitive data exposure and require human review. Raw sensitive values have been masked and are never written to disk or logs.
    </div>
  </div>

  <script>
    const sevCtx = document.getElementById('sevChart').getContext('2d');
    new Chart(sevCtx, {{
      type: 'doughnut',
      data: {{
        labels: {json.dumps(sev_labels)},
        datasets: [{{
          data: {json.dumps(sev_values)},
          backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
          borderWidth: 0
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#94a3b8' }} }} }}
      }}
    }});

    const typeCtx = document.getElementById('typeChart').getContext('2d');
    new Chart(typeCtx, {{
      type: 'bar',
      data: {{
        labels: {json.dumps(type_labels)},
        datasets: [{{
          label: 'Count',
          data: {json.dumps(type_values)},
          backgroundColor: '#38bdf8',
          borderRadius: 4
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ ticks: {{ color: '#94a3b8' }} }},
          y: {{ ticks: {{ color: '#94a3b8', stepSize: 1 }}, beginAtZero: true }}
        }}
      }}
    }});
  </script>
</body>
</html>"""
        return html

    def print_console_summary(self) -> None:
        """Prints a clean summary to the console (FR-7.3)."""
        summary = self.to_dict()["summary"]
        print("\n" + "=" * 65)
        print("[*] SENSITIVE DATA LEAK DETECTOR FOR APIS - SCAN SUMMARY")
        print("=" * 65)
        print(f" Scan Time    : {self.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f" Files Scanned: {summary['total_files_scanned']}")
        print(f" Findings     : {summary['total_findings']}")
        print(f" Overall Risk : {summary['overall_risk_level']} (Score: {summary['risk_score']}/100)")
        print("-" * 65)
        print(" SEVERITY BREAKDOWN:")
        for sev, count in summary["severity_counts"].items():
            print(f"   * {sev:<10}: {count}")
        print("-" * 65)
        print(" TOP FINDINGS:")
        for idx, f in enumerate(self.findings[:8], 1):
            print(f"  [{idx}] {f.severity.upper():<8} | {f.location:<25} | {f.masked_value:<20} | {f.rule_name}")
        if len(self.findings) > 8:
            print(f"  ... and {len(self.findings) - 8} more findings.")
        print("=" * 65)
        print(" NOTE: Results are automated and require human verification.\n")

    def save_report(self, output_path: str | Path, format_type: str = "md") -> None:
        """Saves report to a target file in the requested format (FR-7.4)."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fmt = format_type.lower().lstrip(".")

        if fmt == "json":
            content = self.to_json()
        elif fmt == "csv":
            content = self.to_csv()
        elif fmt in {"html", "htm"}:
            content = self.to_html()
        else:
            content = self.to_markdown()

        path.write_text(content, encoding="utf-8")
