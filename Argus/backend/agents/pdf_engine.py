"""
PDF Report Engine — generates a professional security advisory PDF from a ScanReport.
Uses fpdf2 (pure Python, no system deps).
"""

from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import TYPE_CHECKING

from fpdf import FPDF

if TYPE_CHECKING:
    from backend.models1 import ScanReport


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

_COLORS = {
    "critical": (220, 38, 38),
    "high":     (234, 88, 12),
    "medium":   (202, 138, 4),
    "low":      (22, 163, 74),
    "info":     (59, 130, 246),
    "header":   (15, 23, 42),
    "accent":   (99, 102, 241),
    "bg_light": (241, 245, 249),
}


def _sev_color(severity: str) -> tuple[int, int, int]:
    return _COLORS.get(severity.lower(), _COLORS["info"])


# ---------------------------------------------------------------------------
# PDF builder
# ---------------------------------------------------------------------------


class _ArgusReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, "PROJECT ARGUS — CONFIDENTIAL", align="L")
        self.cell(0, 6, datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*_COLORS["accent"])
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title: str):
        self.ln(4)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*_COLORS["header"])
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*_COLORS["accent"])
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(3)

    def severity_badge(self, severity: str):
        r, g, b = _sev_color(severity)
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        w = self.get_string_width(severity.upper()) + 6
        self.cell(w, 5, severity.upper(), fill=True, align="C")
        self.set_text_color(0, 0, 0)

    def kv(self, key: str, value: str, bold_key: bool = True):
        self.set_font("Helvetica", "B" if bold_key else "", 10)
        self.cell(38, 6, f"{key}:")
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 6, value[:300])


def generate_pdf(report: ScanReport) -> bytes:
    pdf = _ArgusReport()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)

    # ── Title Page ───────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.ln(30)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*_COLORS["header"])
    pdf.cell(0, 15, "Security Assessment Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, f"Target: {report.target}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Scan ID: {report.scan_id}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Date: {report.timestamp.strftime('%Y-%m-%d %H:%M UTC')}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_draw_color(*_COLORS["accent"])
    pdf.set_line_width(0.5)
    pdf.line(60, pdf.get_y(), pdf.w - 60, pdf.get_y())

    # ── Executive Summary ────────────────────────────────────────────────────
    pdf.add_page()
    pdf.section_title("1. Executive Summary")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(30, 30, 30)
    pdf.multi_cell(0, 6, report.executive_summary or "No executive summary available.")
    pdf.ln(4)

    # ── Risk Matrix ──────────────────────────────────────────────────────────
    pdf.section_title("2. Risk Matrix")
    s = report.summary
    matrix = [
        ("Critical", s.critical, "critical"),
        ("High", s.high, "high"),
        ("Medium", s.medium, "medium"),
        ("Low", s.low, "low"),
        ("Info", s.info, "info"),
    ]
    pdf.set_font("Helvetica", "B", 10)
    col_w = 35
    for label, count, sev in matrix:
        r, g, b = _sev_color(sev)
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(col_w, 8, f"{label}: {count}", fill=True, align="C")
        pdf.cell(3)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(14)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Total Vulnerabilities: {s.total_vulnerabilities}", new_x="LMARGIN", new_y="NEXT")

    # ── Detailed Findings ────────────────────────────────────────────────────
    pdf.section_title("3. Detailed Findings")
    for i, v in enumerate(report.vulnerabilities, 1):
        if pdf.get_y() > 240:
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*_COLORS["header"])
        pdf.cell(0, 8, f"3.{i}  {v.title}", new_x="LMARGIN", new_y="NEXT")
        pdf.severity_badge(v.severity.value)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(5)
        pdf.cell(0, 5, f"CVSS {v.cvss_score:.1f}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        pdf.set_text_color(0, 0, 0)
        pdf.kv("Type", v.type)
        pdf.kv("Endpoint", f"{v.method} {v.endpoint}")
        if v.payload:
            pdf.kv("Payload", v.payload)
        if v.evidence:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(38, 6, "Evidence:")
            pdf.ln()
            pdf.set_fill_color(*_COLORS["bg_light"])
            pdf.set_font("Courier", "", 8)
            pdf.multi_cell(0, 4, v.evidence[:500], fill=True)
            pdf.ln(2)
        pdf.kv("Remediation", v.remediation)
        if v.patch_code:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(38, 6, "Patch Code:")
            pdf.ln()
            pdf.set_fill_color(*_COLORS["bg_light"])
            pdf.set_font("Courier", "", 8)
            pdf.multi_cell(0, 4, v.patch_code[:400], fill=True)
            pdf.ln(2)
        pdf.ln(4)

    # ── CVE Findings ─────────────────────────────────────────────────────────
    if report.cve_findings:
        pdf.section_title("4. CVE Intelligence")
        for c in report.cve_findings:
            if pdf.get_y() > 245:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*_COLORS["header"])
            pdf.cell(0, 7, f"{c.cve_id}  (CVSS {c.cvss_score:.1f})", new_x="LMARGIN", new_y="NEXT")
            pdf.severity_badge(c.severity.value)
            if c.exploit_available:
                pdf.cell(3)
                pdf.set_fill_color(220, 38, 38)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 8)
                pdf.cell(25, 5, "EXPLOIT", fill=True, align="C")
            pdf.ln(2)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 9)
            pdf.kv("Service", f"{c.service} {c.version}")
            pdf.multi_cell(0, 5, c.description[:300])
            if c.exploit_db_url:
                pdf.kv("Exploit-DB", c.exploit_db_url)
            if c.patch_url:
                pdf.kv("Patch URL", c.patch_url)
            if c.fixed_in_version:
                pdf.kv("Fixed In", c.fixed_in_version)
            pdf.ln(4)

    # ── Attack Chains ────────────────────────────────────────────────────────
    if report.attack_chains:
        pdf.section_title("5. Attack Chains")
        for chain in report.attack_chains:
            if pdf.get_y() > 240:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*_COLORS["header"])
            pdf.cell(0, 8, chain.title, new_x="LMARGIN", new_y="NEXT")
            pdf.severity_badge(chain.severity.value)
            pdf.ln(2)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 5, chain.description)
            pdf.ln(2)
            for step in chain.steps:
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(20, 5, f"Step {step.step_number}:")
                pdf.set_font("Helvetica", "", 9)
                pdf.multi_cell(0, 5, f"{step.action} -> {step.outcome}")
            pdf.kv("Impact", chain.impact)
            pdf.ln(4)

    # ── Remediation Priority ─────────────────────────────────────────────────
    if report.remediation_priority:
        pdf.section_title("6. Remediation Priority")
        pdf.set_font("Helvetica", "", 10)
        for idx, item in enumerate(report.remediation_priority, 1):
            pdf.cell(0, 6, f"  {idx}. {item}", new_x="LMARGIN", new_y="NEXT")

    # ── Tested — Not Vulnerable (Dismissed Findings) ──────────────────────
    if report.dismissed_findings:
        pdf.section_title("7. Tested — Not Vulnerable")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 30, 30)
        pdf.multi_cell(
            0, 6,
            "The following hypotheses were tested by child agents and verified as "
            "FALSE. These are documented to prove testing thoroughness and to confirm "
            "that these attack vectors do not exist on the target.",
        )
        pdf.ln(4)
        for i, d in enumerate(report.dismissed_findings, 1):
            if pdf.get_y() > 240:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*_COLORS["header"])
            pdf.cell(0, 7, f"7.{i}  {d.type} — {d.endpoint}", new_x="LMARGIN", new_y="NEXT")
            # Green "CLEAR" badge
            pdf.set_fill_color(22, 163, 74)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(18, 5, "CLEAR", fill=True, align="C")
            pdf.ln(2)
            pdf.set_text_color(0, 0, 0)
            pdf.kv("Hypothesis", d.hypothesis)
            pdf.kv("Tool Used", d.tool_used)
            pdf.kv("Result", d.verification_result)
            pdf.kv("Agent", d.agent)
            pdf.ln(3)

    # ── Output ───────────────────────────────────────────────────────────────
    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()
