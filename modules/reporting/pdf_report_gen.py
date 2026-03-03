"""
pdf_report_gen.py — Professional Pentest PDF Report (Full Evidence Edition)

This report shows EXACTLY what was done, HOW each tool works,
WHY each technique was chosen, WHAT was observed in real HTTP
traffic, and WHY it matters to the business.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas as rl_canvas

from typing import List, Dict, Any, Optional
from datetime import datetime
import os

# ── Colour Palette ─────────────────────────────────────────────────────────────
C_DARK_NAVY  = colors.HexColor("#0A1628")
C_NAVY       = colors.HexColor("#1B2A4A")
C_STEEL      = colors.HexColor("#2C3E6B")
C_ACCENT     = colors.HexColor("#00B4D8")
C_WHITE      = colors.HexColor("#FFFFFF")
C_LIGHT_GREY = colors.HexColor("#F5F7FA")
C_MID_GREY   = colors.HexColor("#C8D0DC")
C_TEXT       = colors.HexColor("#1A1A2E")
C_SUBTEXT    = colors.HexColor("#4A5568")
C_CODE_BG    = colors.HexColor("#0D1117")
C_CODE_TEXT  = colors.HexColor("#E6EDF3")
C_GREEN_CODE = colors.HexColor("#3FB950")
C_YELLOW     = colors.HexColor("#D29922")

SEV = {
    "CRITICAL": colors.HexColor("#D90429"),
    "HIGH":     colors.HexColor("#EF6C00"),
    "MEDIUM":   colors.HexColor("#F9A825"),
    "LOW":      colors.HexColor("#2E7D32"),
    "INFO":     colors.HexColor("#1565C0"),
}
SEV_BG = {
    "CRITICAL": colors.HexColor("#FFF0F0"),
    "HIGH":     colors.HexColor("#FFF5EC"),
    "MEDIUM":   colors.HexColor("#FFFDE7"),
    "LOW":      colors.HexColor("#F1F8E9"),
    "INFO":     colors.HexColor("#E3F2FD"),
}
SEVERITY_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}


# ── Custom Flowables ───────────────────────────────────────────────────────────

class DarkBar(Flowable):
    def __init__(self, width, height, color, text="", font_size=10):
        super().__init__()
        self.bw=width; self.bh=height; self.color=color; self.text=text; self.fs=font_size
    def wrap(self,*a): return self.bw, self.bh
    def draw(self):
        c=self.canv
        c.setFillColor(self.color); c.rect(0,0,self.bw,self.bh,fill=1,stroke=0)
        if self.text:
            c.setFillColor(C_WHITE); c.setFont("Helvetica-Bold",self.fs)
            c.drawString(10,(self.bh-self.fs)/2+2,self.text)

class CVSSBar(Flowable):
    def __init__(self, score, width=120*mm):
        super().__init__()
        self.score=score; self.bw=width; self.bh=14
    def wrap(self,*a): return self.bw+40*mm, self.bh+4
    def draw(self):
        c=self.canv; s=float(self.score)
        col=(SEV["CRITICAL"] if s>=9 else SEV["HIGH"] if s>=7 else SEV["MEDIUM"] if s>=4 else SEV["LOW"])
        c.setFillColor(C_LIGHT_GREY); c.rect(0,2,self.bw,10,fill=1,stroke=0)
        c.setFillColor(col); c.rect(0,2,self.bw*(s/10),10,fill=1,stroke=0)
        c.setFillColor(col); c.setFont("Helvetica-Bold",9)
        c.drawString(self.bw+4,3,f"CVSS {s:.1f}/10.0")


# ── Page Canvas (header/footer on every page) ─────────────────────────────────

class ReportCanvas(rl_canvas.Canvas):
    def __init__(self, *args, meta=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.meta = meta or {}
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        n = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._chrome(n)
            super().showPage()
        super().save()

    def _chrome(self, total):
        w,h = A4; pg = self._pageNumber
        if pg > 1:
            self.setFillColor(C_DARK_NAVY)
            self.rect(0, h-20*mm, w, 20*mm, fill=1, stroke=0)
            self.setFillColor(C_ACCENT); self.rect(0, h-20*mm, 3, 20*mm, fill=1, stroke=0)
            self.setFont("Helvetica-Bold",8); self.setFillColor(C_WHITE)
            self.drawString(10*mm, h-11*mm, self.meta.get("program","Penetration Test Report"))
            self.setFont("Helvetica",7); self.setFillColor(C_ACCENT)
            self.drawRightString(w-10*mm, h-11*mm, f"Target: {self.meta.get('target','')}")
            self.setFont("Helvetica-Bold",6.5); self.setFillColor(colors.HexColor("#EF6C00"))
            self.drawRightString(w-10*mm, h-17*mm, "CONFIDENTIAL")

        self.setFillColor(C_LIGHT_GREY); self.rect(0,0,w,13*mm,fill=1,stroke=0)
        self.setStrokeColor(C_ACCENT); self.setLineWidth(0.5); self.line(0,13*mm,w,13*mm)
        self.setFont("Helvetica",7); self.setFillColor(C_SUBTEXT)
        self.drawString(10*mm,4*mm,f"Prepared by: {self.meta.get('tester','')}  |  {self.meta.get('date','')}")
        self.drawRightString(w-10*mm,4*mm,f"Page {pg} / {total}")

        if pg > 1:
            self.saveState()
            self.setFont("Helvetica-Bold",44); self.setFillColor(colors.Color(0,0,0,alpha=0.025))
            self.translate(w/2,h/2); self.rotate(45)
            self.drawCentredString(0,0,"CONFIDENTIAL"); self.restoreState()


# ── Style factory ─────────────────────────────────────────────────────────────

def styles():
    base = getSampleStyleSheet()
    def S(n,p="Normal",**kw): return ParagraphStyle(n,parent=base[p],**kw)
    return {
        "cover_title":   S("ct","Title",fontSize=26,leading=32,textColor=C_WHITE,fontName="Helvetica-Bold",alignment=TA_CENTER),
        "cover_sub":     S("cs",fontSize=12,textColor=C_ACCENT,fontName="Helvetica",alignment=TA_CENTER),
        "cover_meta":    S("cm",fontSize=9,textColor=C_MID_GREY,fontName="Helvetica",alignment=TA_CENTER),
        "section":       S("sec","Heading1",fontSize=13,leading=17,textColor=C_WHITE,fontName="Helvetica-Bold",spaceBefore=0,spaceAfter=0),
        "h2":            S("h2","Heading2",fontSize=11,leading=15,textColor=C_NAVY,fontName="Helvetica-Bold",spaceBefore=10,spaceAfter=4),
        "h3":            S("h3","Heading3",fontSize=10,leading=13,textColor=C_STEEL,fontName="Helvetica-Bold",spaceBefore=7,spaceAfter=3),
        "body":          S("body",fontSize=9,leading=13,textColor=C_TEXT,fontName="Helvetica",alignment=TA_JUSTIFY),
        "body_b":        S("bodyb",fontSize=9,leading=13,textColor=C_TEXT,fontName="Helvetica-Bold"),
        "label":         S("lbl",fontSize=8,leading=11,textColor=C_SUBTEXT,fontName="Helvetica-Bold"),
        "code":          S("code",fontSize=7.5,leading=11,textColor=C_CODE_TEXT,fontName="Courier",
                           backColor=C_CODE_BG,leftIndent=8,rightIndent=8,spaceBefore=3,spaceAfter=3,
                           borderColor=colors.HexColor("#30363D"),borderWidth=0.5,borderPadding=7),
        "code_comment":  S("cc",fontSize=7,leading=10,textColor=C_GREEN_CODE,fontName="Courier",
                           backColor=C_CODE_BG,leftIndent=8,borderPadding=3),
        "http_req":      S("hr",fontSize=7.5,leading=11,textColor=colors.HexColor("#79C0FF"),fontName="Courier",
                           backColor=C_CODE_BG,leftIndent=8,borderPadding=6,borderWidth=0.5,
                           borderColor=colors.HexColor("#388BFD")),
        "http_resp_ok":  S("hrok",fontSize=7.5,leading=11,textColor=colors.HexColor("#56D364"),fontName="Courier",
                           backColor=C_CODE_BG,leftIndent=8,borderPadding=6,borderWidth=0.5,
                           borderColor=colors.HexColor("#238636")),
        "http_resp_err": S("hrerr",fontSize=7.5,leading=11,textColor=colors.HexColor("#FF7B72"),fontName="Courier",
                           backColor=C_CODE_BG,leftIndent=8,borderPadding=6,borderWidth=0.5,
                           borderColor=colors.HexColor("#DA3633")),
        "highlight":     S("hl",fontSize=8,leading=12,textColor=C_TEXT,fontName="Helvetica",
                           backColor=colors.HexColor("#FFF9C4"),leftIndent=8,
                           borderColor=C_YELLOW,borderWidth=1.5,borderPadding=6,spaceBefore=3,spaceAfter=3),
        "narrative":     S("nar",fontSize=9,leading=13,textColor=C_TEXT,fontName="Helvetica",
                           backColor=colors.HexColor("#F0F4FF"),leftIndent=10,
                           borderColor=C_ACCENT,borderWidth=1.5,borderPadding=8,spaceBefore=3,spaceAfter=5),
        "caption":       S("cap",fontSize=7.5,leading=10,textColor=C_SUBTEXT,fontName="Helvetica-Oblique",alignment=TA_CENTER),
        "disclaimer":    S("dis",fontSize=7.5,leading=11,textColor=C_SUBTEXT,fontName="Helvetica-Oblique",alignment=TA_JUSTIFY),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def sec_header(title, st, W):
    return [Spacer(1,8), DarkBar(W, 22, C_DARK_NAVY, f"  {title}", font_size=10), Spacer(1,8)]

def esc(text):
    """Escape XML special chars for ReportLab Paragraph."""
    if not text: return ""
    return str(text).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def fmt_http_request(req) -> str:
    """Format an HTTPRequestRecord as a raw HTTP message."""
    if req is None: return "[no request recorded]"
    try:
        from urllib.parse import urlencode
        params_str = urlencode(req.params) if req.params else ""
        path = req.url.split("://",1)[-1].split("/",1)[-1] if "/" in req.url.split("://",1)[-1] else "/"
        if not path.startswith("/"): path = "/" + path
        if params_str: path += "?" + params_str
        host = req.url.split("://",1)[-1].split("/")[0]
        lines = [f"{req.method} {path} HTTP/1.1", f"Host: {host}"]
        for k,v in list(req.headers.items())[:6]:
            if k.lower() not in ("host",):
                lines.append(f"{k}: {v[:80]}")
        if req.body:
            lines += ["", req.body[:200]]
        return "\n".join(lines)
    except Exception:
        return str(req)

def fmt_http_response(resp) -> str:
    """Format an HTTPResponseRecord as a raw HTTP message."""
    if resp is None: return "[no response recorded]"
    try:
        status_text = {200:"OK",301:"Moved Permanently",302:"Found",400:"Bad Request",
                       401:"Unauthorized",403:"Forbidden",404:"Not Found",500:"Internal Server Error"}.get(resp.status_code,"")
        lines = [f"HTTP/1.1 {resp.status_code} {status_text}",
                 f"Content-Type: {resp.content_type}",
                 f"Content-Length: {resp.full_body_length}",
                 f"Response-Time: {resp.response_time_ms:.0f}ms"]
        for k,v in list(resp.headers.items())[:5]:
            if k.lower() not in ("content-type","content-length"):
                lines.append(f"{k}: {str(v)[:80]}")
        body = resp.body_snippet[:600] if resp.body_snippet else ""
        if body:
            lines += ["", "--- Response Body (truncated) ---", body]
        return "\n".join(lines)
    except Exception:
        return str(resp)


def build_step_table(steps, st, W):
    """Build the step-by-step attack table with full detail."""
    if not steps: return []
    result = []
    for step in steps:
        n = step.get("step","?")
        action = step.get("action","")
        sev_color = C_NAVY

        # Step header
        step_bar = DarkBar(W, 18, C_STEEL, f"  Step {n}: {action}", font_size=9)
        result.append(step_bar)

        rows = []
        fields = [
            ("What was done",    step.get("what_was_done","")),
            ("Tool used",        step.get("tool_used","")),
            ("Why this tool",    step.get("why","")),
            ("What was observed",step.get("what_was_observed","")),
            ("What it means",    step.get("what_it_means","")),
        ]
        for label, value in fields:
            if value:
                rows.append([
                    Paragraph(label, st["label"]),
                    Paragraph(esc(str(value)[:400]), st["body"]),
                ])

        if rows:
            t = Table(rows, colWidths=[38*mm, W-41*mm])
            t.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,-1), SEV_BG.get("INFO", C_LIGHT_GREY)),
                ("BACKGROUND",   (0,0),(0,-1),  colors.HexColor("#E8EDF5")),
                ("GRID",         (0,0),(-1,-1),  0.3, C_MID_GREY),
                ("VALIGN",       (0,0),(-1,-1),  "TOP"),
                ("TOPPADDING",   (0,0),(-1,-1),  4),
                ("BOTTOMPADDING",(0,0),(-1,-1),  4),
                ("LEFTPADDING",  (0,0),(-1,-1),  5),
            ]))
            result.append(t)

        # Raw evidence block (actual error text from server)
        raw = step.get("raw_evidence","")
        if raw:
            result.append(Paragraph("▶ Raw server response (the proof):", st["label"]))
            result.append(Paragraph(esc(raw[:500]), st["http_resp_err"]))

        result.append(Spacer(1,4))
    return result


def build_finding_block(finding, st, W, idx):
    """Build the complete PDF block for one finding — the full story."""
    sev    = finding.get("severity","INFO")
    sev_c  = SEV.get(sev, C_STEEL)
    cvss   = finding.get("cvss", "N/A")
    ftype  = finding.get("type","Unknown")
    ev     = finding.get("evidence_record")

    block = [Spacer(1,12)]

    # ── Finding header ──
    block.append(DarkBar(W, 26, sev_c, f"  Finding #{idx}: {ftype}", font_size=9))

    # ── Quick facts row ──
    qf_data = [[
        Paragraph(f"<b>Severity:</b> {sev}", st["body"]),
        Paragraph(f"<b>CVSS:</b> {cvss}", st["body"]),
        Paragraph(f"<b>Parameter / Vector:</b> {esc(str(finding.get('param','N/A'))[:40])}", st["body"]),
        Paragraph(f"<b>Discovered by:</b> {esc(finding.get('module','Scanner') if not ev else ev.module)}", st["body"]),
    ]]
    qft = Table(qf_data, colWidths=[W/4]*4)
    qft.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1), SEV_BG.get(sev,C_LIGHT_GREY)),
        ("GRID",(0,0),(-1,-1),0.3,C_MID_GREY),
        ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),6),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    block.append(qft)
    block.append(Spacer(1,6))

    # ── Affected URL ──
    block.append(Paragraph("<b>Affected URL:</b>", st["label"]))
    block.append(Paragraph(esc(finding.get("url","")), st["code"]))
    block.append(Spacer(1,4))

    # ── CVSS Score bar ──
    if isinstance(cvss,(int,float)):
        block.append(Paragraph("<b>CVSS v3.1 Score:</b>", st["label"]))
        block.append(CVSSBar(float(cvss), W*0.6))
        block.append(Spacer(1,4))

    # ── CVSS Breakdown ──
    if ev and ev.cvss_breakdown:
        cb = ev.cvss_breakdown
        block.append(Paragraph("CVSS v3.1 Vector Breakdown", st["h3"]))
        cvss_rows = [
            [Paragraph("Vector String",st["label"]),   Paragraph(esc(cb.vector_string),st["code"])],
            [Paragraph("Attack Vector",st["label"]),   Paragraph(esc(cb.attack_vector),st["body"])],
            [Paragraph("Attack Complexity",st["label"]),Paragraph(esc(cb.attack_complexity),st["body"])],
            [Paragraph("Privileges Required",st["label"]),Paragraph(esc(cb.privileges_required),st["body"])],
            [Paragraph("User Interaction",st["label"]),Paragraph(esc(cb.user_interaction),st["body"])],
            [Paragraph("Scope",st["label"]),           Paragraph(esc(cb.scope),st["body"])],
            [Paragraph("Confidentiality",st["label"]), Paragraph(esc(cb.confidentiality),st["body"])],
            [Paragraph("Integrity",st["label"]),       Paragraph(esc(cb.integrity),st["body"])],
            [Paragraph("Availability",st["label"]),    Paragraph(esc(cb.availability),st["body"])],
        ]
        cvss_t = Table(cvss_rows, colWidths=[40*mm, W-43*mm])
        cvss_t.setStyle(TableStyle([
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_WHITE, C_LIGHT_GREY]),
            ("GRID",(0,0),(-1,-1),0.3,C_MID_GREY),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
            ("LEFTPADDING",(0,0),(-1,-1),5),
        ]))
        block.append(cvss_t)
        block.append(Spacer(1,8))

    # ── Tool Explanation ──────────────────────────────────────────────────────
    if ev and ev.tool_explanation:
        te = ev.tool_explanation
        block.append(DarkBar(W, 18, C_NAVY, "  Tool & Technique Explanation", font_size=9))
        tool_rows = [
            [Paragraph("Tool Used",st["label"]),          Paragraph(esc(te.tool_name),st["body_b"])],
            [Paragraph("Why This Tool",st["label"]),      Paragraph(esc(te.why_this_tool),st["body"])],
            [Paragraph("How It Works",st["label"]),       Paragraph(esc(te.how_it_works),st["body"])],
            [Paragraph("What Output Means",st["label"]),  Paragraph(esc(te.what_output_means),st["body"])],
        ]
        tt = Table(tool_rows, colWidths=[38*mm, W-41*mm])
        tt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F0F4FF")),
            ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#E0E8FF")),
            ("GRID",(0,0),(-1,-1),0.3,C_MID_GREY),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("LEFTPADDING",(0,0),(-1,-1),6),
        ]))
        block.append(tt)
        block.append(Spacer(1,8))

    # ── LIVE HTTP Evidence ────────────────────────────────────────────────────
    block.append(DarkBar(W, 18, C_NAVY, "  Live HTTP Evidence — Actual Traffic Captured During Test", font_size=9))

    # Baseline (if available)
    if ev and ev.additional_requests:
        for extra in ev.additional_requests:
            if "baseline" in extra.get("label","").lower():
                block.append(Paragraph(f"▶ {extra.get('label','Baseline Request')}:", st["label"]))
                block.append(Paragraph(f"  Purpose: {esc(extra.get('purpose',''))}", st["caption"]))
                req_text = f"{extra.get('method','GET')} {extra.get('url','')}?{extra.get('params','')}"
                block.append(Paragraph(esc(req_text[:200]), st["http_req"]))
                block.append(Paragraph(
                    f"HTTP {extra.get('status_code','?')} — {extra.get('response_len',0):,} bytes — Normal response, no errors",
                    st["http_resp_ok"]))
                block.append(Spacer(1,4))

    # The actual attack request
    if ev and ev.request:
        block.append(Paragraph("▶ Attack Request (sent by scanner):", st["label"]))
        block.append(Paragraph(f"  Purpose: {esc(ev.request.purpose)}", st["caption"]))
        block.append(Paragraph(esc(fmt_http_request(ev.request)), st["http_req"]))

    if ev and ev.response:
        resp_style = st["http_resp_err"] if ev.response.status_code >= 400 else st["http_resp_ok"]
        block.append(Paragraph("▶ Server Response (received by scanner):", st["label"]))
        block.append(Paragraph(esc(fmt_http_response(ev.response)), resp_style))
        block.append(Spacer(1,4))

    # Boolean diff evidence
    if ev and ev.diff:
        d = ev.diff
        block.append(Paragraph("▶ Differential Analysis (Boolean Blind Proof):", st["label"]))
        diff_data = [
            [Paragraph("TRUE condition request",st["label"]),  Paragraph(esc(d.baseline_request),st["code"])],
            [Paragraph("TRUE response size",st["label"]),      Paragraph(f"{d.baseline_response_length:,} bytes (HTTP {d.baseline_status})",st["body"])],
            [Paragraph("FALSE condition request",st["label"]), Paragraph(esc(d.probe_request),st["code"])],
            [Paragraph("FALSE response size",st["label"]),     Paragraph(f"{d.probe_response_length:,} bytes (HTTP {d.probe_status})",st["body"])],
            [Paragraph("Size differential",st["label"]),       Paragraph(f"<b>Δ {d.length_delta:,} bytes</b> — significant difference confirms server evaluates injected SQL",st["body_b"])],
            [Paragraph("Interpretation",st["label"]),          Paragraph(esc(d.interpretation),st["narrative"])],
        ]
        diff_t = Table(diff_data, colWidths=[40*mm, W-43*mm])
        diff_t.setStyle(TableStyle([
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_LIGHT_GREY, C_WHITE]),
            ("GRID",(0,0),(-1,-1),0.3,C_MID_GREY),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("LEFTPADDING",(0,0),(-1,-1),5),
        ]))
        block.append(diff_t)

    # Proof statement
    if ev and ev.proof_statement:
        block.append(Spacer(1,4))
        block.append(Paragraph("▶ Proof Statement:", st["label"]))
        block.append(Paragraph(esc(ev.proof_statement), st["highlight"]))

    block.append(Spacer(1,8))

    # ── Step-by-Step Attack Narrative ─────────────────────────────────────────
    if ev and ev.attack_steps:
        block.append(DarkBar(W, 18, C_NAVY, "  Step-by-Step Attack Narrative", font_size=9))
        block.append(Paragraph(
            "The following table documents every action taken during this finding's discovery and validation. "
            "This is the exact sequence — what was done, the tool used, why that tool, what was observed, "
            "and what each observation proves.",
            st["body"]))
        block.append(Spacer(1,6))
        block.extend(build_step_table(ev.attack_steps, st, W))

    # ── Reproduction Commands ─────────────────────────────────────────────────
    if ev and (ev.curl_command or ev.burp_steps):
        block.append(Spacer(1,6))
        block.append(DarkBar(W, 18, C_STEEL, "  Reproduction Commands", font_size=9))

        if ev.curl_command:
            block.append(Paragraph("cURL / sqlmap (copy-paste ready):", st["h3"]))
            block.append(Paragraph(esc(ev.curl_command), st["code"]))

        if ev.burp_steps:
            block.append(Paragraph("Burp Suite Steps:", st["h3"]))
            block.append(Paragraph(esc(ev.burp_steps).replace("\n","<br/>"), st["body"]))

    block.append(Spacer(1,6))

    # ── Business Impact ───────────────────────────────────────────────────────
    if ev and ev.business_impact:
        bi = ev.business_impact
        block.append(DarkBar(W, 18, SEV.get(sev, C_NAVY), "  Business Impact & Risk Analysis", font_size=9))
        bi_rows = [
            [Paragraph("What attacker can do",st["label"]),        Paragraph(esc(bi.what_attacker_can_do),st["body"])],
            [Paragraph("Data at risk",st["label"]),                 Paragraph(esc(bi.data_at_risk),st["body"])],
            [Paragraph("Worst-case scenario",st["label"]),          Paragraph(esc(bi.worst_case_scenario),st["body"])],
            [Paragraph("Affected users",st["label"]),               Paragraph(esc(bi.affected_users),st["body"])],
            [Paragraph("Regulatory implications",st["label"]),      Paragraph(esc(bi.regulatory_implications),st["body"])],
            [Paragraph("Severity rationale",st["label"]),           Paragraph(esc(bi.estimated_severity_rationale),st["body"])],
        ]
        bit = Table(bi_rows, colWidths=[40*mm, W-43*mm])
        bit.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1), SEV_BG.get(sev,C_LIGHT_GREY)),
            ("BACKGROUND",(0,0),(0,-1),  colors.HexColor("#FDECEA") if sev in ("CRITICAL","HIGH") else C_LIGHT_GREY),
            ("GRID",(0,0),(-1,-1),0.3,C_MID_GREY),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("LEFTPADDING",(0,0),(-1,-1),6),
        ]))
        block.append(bit)

    block.append(Spacer(1,8))

    # ── Remediation ───────────────────────────────────────────────────────────
    block.append(Paragraph("Remediation", st["h3"]))
    block.append(Paragraph(esc(finding.get("remediation","See OWASP guidelines.")), st["body"]))

    return block


# ── Main Entry Point ──────────────────────────────────────────────────────────

def generate_pdf_report(scan_data: Dict, output_path: str) -> str:
    doc = SimpleDocTemplate(output_path, pagesize=A4,
        rightMargin=18*mm, leftMargin=18*mm, topMargin=26*mm, bottomMargin=18*mm)
    W = A4[0] - 36*mm
    st = styles()

    all_findings = sorted(
        scan_data.get("all_findings",[]),
        key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"),99))

    counts = {s: sum(1 for f in all_findings if f.get("severity")==s)
              for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}

    def risk_score(fs):
        w={"CRITICAL":10,"HIGH":7,"MEDIUM":4,"LOW":2,"INFO":0.5}
        if not fs: return 0.0
        return round(min(10.0, sum(w.get(f.get("severity","INFO"),0) for f in fs)/max(len(fs),1)),1)

    rs = risk_score(all_findings)
    rc = SEV["CRITICAL"] if rs>=8 else SEV["HIGH"] if rs>=6 else SEV["MEDIUM"] if rs>=4 else SEV["LOW"]

    meta = {
        "program": scan_data.get("program_name","Penetration Test"),
        "target":  scan_data.get("target",""),
        "tester":  scan_data.get("tester_name","Security Researcher"),
        "date":    scan_data.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d")),
    }

    story = []

    # ══ COVER ══
    cover = Table([[Paragraph("",st["body"])]], colWidths=[W], rowHeights=[260])
    cover.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_DARK_NAVY),("ROUNDEDCORNERS",(0,0),(-1,-1),6)]))
    story.append(cover)
    story.append(Spacer(1,-260))
    for item in [
        Spacer(1,28),
        Paragraph("BUG BOUNTY HUNTER PLATFORM", st["cover_sub"]),
        Spacer(1,6),
        Paragraph("Penetration Test Report", st["cover_title"]),
        Spacer(1,14),
        Paragraph(esc(scan_data.get("program_name","Security Assessment")),
                  ParagraphStyle("pp",fontSize=15,textColor=C_ACCENT,fontName="Helvetica-Bold",alignment=TA_CENTER)),
        Spacer(1,16),
        Paragraph(f"<b>Target:</b> {esc(scan_data.get('target',''))}", st["cover_meta"]),
        Paragraph(f"<b>Company:</b> {esc(scan_data.get('company_name','N/A'))}", st["cover_meta"]),
        Paragraph(f"<b>Date:</b> {esc(scan_data.get('timestamp',''))}", st["cover_meta"]),
        Spacer(1,16),
        Paragraph("⚠ CONFIDENTIAL — FOR AUTHORISED RECIPIENTS ONLY",
                  ParagraphStyle("warn",fontSize=8,textColor=colors.HexColor("#EF6C00"),fontName="Helvetica-Bold",alignment=TA_CENTER)),
    ]: story.append(item)

    story.append(Spacer(1,14))
    badge = Table([[
        Paragraph("RISK SCORE",ParagraphStyle("rsl",fontSize=8,textColor=C_SUBTEXT,fontName="Helvetica-Bold",alignment=TA_CENTER)),
        Paragraph(f"{rs}/10",ParagraphStyle("rsn",fontSize=22,textColor=rc,fontName="Helvetica-Bold",alignment=TA_CENTER)),
        Paragraph(f"{len(all_findings)} FINDINGS",ParagraphStyle("rsf",fontSize=8,textColor=C_SUBTEXT,fontName="Helvetica-Bold",alignment=TA_CENTER)),
    ]], colWidths=[W/3]*3)
    badge.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_LIGHT_GREY),("GRID",(0,0),(-1,-1),0.5,C_MID_GREY),
        ("TOPPADDING",(0,0),(-1,-1),10),("BOTTOMPADDING",(0,0),(-1,-1),10),("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
    story.append(badge)
    story.append(Spacer(1,12))
    story.append(Paragraph(
        f"Prepared by: <b>{esc(scan_data.get('tester_name',''))}</b>  |  Engagement ID: <b>{esc(scan_data.get('engagement_id','N/A'))}</b>",
        ParagraphStyle("ti",fontSize=8.5,textColor=C_SUBTEXT,fontName="Helvetica",alignment=TA_CENTER)))
    story.append(PageBreak())

    # ══ EXECUTIVE SUMMARY ══
    story += sec_header("1. EXECUTIVE SUMMARY", st, W)
    story.append(Paragraph(
        f"This report documents a full-scope security assessment against "
        f"<b>{esc(scan_data.get('target','the target'))}</b>. "
        f"All testing was conducted within the authorised scope. "
        f"<b>{len(all_findings)} findings</b> were identified: "
        f"<b>{counts['CRITICAL']} Critical</b>, <b>{counts['HIGH']} High</b>, "
        f"<b>{counts['MEDIUM']} Medium</b>, <b>{counts['LOW']} Low</b>, <b>{counts['INFO']} Info</b>. "
        f"Overall risk score: <b>{rs}/10</b>.", st["body"]))
    story.append(Spacer(1,8))

    sev_tbl = Table([
        [Paragraph("Severity",st["label"]), Paragraph("Count",st["label"]),
         Paragraph("Timeline",st["label"]), Paragraph("Description",st["label"])],
    ]+[
        [Paragraph(f'<font color="{SEV[s].hexval()}">{s}</font>',st["body_b"]),
         Paragraph(str(counts[s]),st["body"]),
         Paragraph({"CRITICAL":"24-72 hrs","HIGH":"1-2 weeks","MEDIUM":"1 month","LOW":"Next quarter","INFO":"Ongoing"}[s],st["body"]),
         Paragraph({"CRITICAL":"Immediate exploitation possible; critical data breach risk",
                    "HIGH":"Significant impact; exploitable with moderate effort",
                    "MEDIUM":"Limited impact; specific conditions required",
                    "LOW":"Minimal direct risk; defence-in-depth issue",
                    "INFO":"Best-practice improvement"}[s],st["body"])]
        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    ], colWidths=[25*mm,16*mm,22*mm,W-68*mm], repeatRows=1)
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),C_NAVY),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LIGHT_GREY]),
        ("GRID",(0,0),(-1,-1),0.3,C_MID_GREY),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),("LEFTPADDING",(0,0),(-1,-1),5),
    ]))
    story.append(sev_tbl)
    story.append(PageBreak())

    # ══ SCOPE ══
    story += sec_header("2. SCOPE & RULES OF ENGAGEMENT", st, W)
    scope = scan_data.get("scope_summary",{})
    story.append(Paragraph(
        "All testing was bounded by the scope definition below. The platform's scope enforcement engine "
        "automatically blocked any request to assets not listed as in-scope and logged all violations.",
        st["body"]))
    story.append(Spacer(1,6))
    for label,val in [("Program",scan_data.get("program_name","N/A")),
                       ("Company",scan_data.get("company_name","N/A")),
                       ("Target URL",scan_data.get("target","N/A")),
                       ("Engagement ID",scan_data.get("engagement_id","N/A")),
                       ("Date",scan_data.get("timestamp","N/A")),
                       ("Tester",scan_data.get("tester_name","N/A"))]:
        row = Table([[Paragraph(label,st["label"]),Paragraph(esc(str(val)),st["body"])]],colWidths=[40*mm,W-43*mm])
        row.setStyle(TableStyle([("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2),("LEFTPADDING",(0,0),(-1,-1),0)]))
        story.append(row)
    story.append(Spacer(1,6))
    story.append(Paragraph("In-Scope Targets", st["h2"]))
    for d in scope.get("in_scope_domains",[scan_data.get("target","")]):
        story.append(Paragraph(f"• {esc(d)}",st["body"]))
    oos = scope.get("out_of_scope_domains",[])
    if oos:
        story.append(Paragraph("Explicitly Out-of-Scope (blocked by scope engine)", st["h2"]))
        for d in oos: story.append(Paragraph(f"• {esc(d)}",st["body"]))
    violations = scan_data.get("scope_violations",[])
    if violations:
        story.append(Paragraph(f"⚠ {len(violations)} out-of-scope request(s) automatically blocked and not tested.",
                               ParagraphStyle("vw",fontSize=9,textColor=SEV["MEDIUM"],fontName="Helvetica-Bold")))
    story.append(Spacer(1,6))
    story.append(Paragraph("Rules of Engagement",st["h2"]))
    story.append(Paragraph(esc(scan_data.get("rules_of_engagement","All testing conducted within authorised scope.")),st["body"]))
    story.append(PageBreak())

    # ══ FINDINGS INDEX ══
    story += sec_header("3. FINDINGS INDEX", st, W)
    idx_rows = [[Paragraph(h,st["label"]) for h in ["#","Finding","Severity","CVSS","URL"]]]
    for i,f in enumerate(all_findings,1):
        s=f.get("severity","INFO")
        idx_rows.append([
            Paragraph(str(i),st["body"]),
            Paragraph(esc(f.get("type","?")[:55]),st["body"]),
            Paragraph(f'<font color="{SEV.get(s,C_STEEL).hexval()}"><b>{s}</b></font>',st["body"]),
            Paragraph(str(f.get("cvss","N/A")),st["body"]),
            Paragraph(esc(f.get("url","")[:45]),st["code"]),
        ])
    idx_t = Table(idx_rows,colWidths=[10*mm,65*mm,22*mm,16*mm,W-118*mm],repeatRows=1)
    idx_t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),C_NAVY),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LIGHT_GREY]),
        ("GRID",(0,0),(-1,-1),0.3,C_MID_GREY),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),("LEFTPADDING",(0,0),(-1,-1),5),
    ]))
    story.append(idx_t)
    story.append(PageBreak())

    # ══ DETAILED FINDINGS — FULL EVIDENCE ══
    story += sec_header("4. DETAILED FINDINGS — FULL EVIDENCE & ATTACK NARRATIVES", st, W)
    story.append(Paragraph(
        "Every finding below documents the complete picture: the tool used and why it was chosen, "
        "how the tool works mechanically, the exact HTTP requests sent and responses received, "
        "step-by-step what was done and what each step proved, copy-paste reproduction commands, "
        "and a business impact analysis translating the technical finding into organisational risk.",
        st["body"]))

    if not all_findings:
        story.append(Spacer(1,20))
        story.append(Paragraph("No vulnerabilities were found during this assessment.", st["h2"]))
    else:
        for i, finding in enumerate(all_findings, 1):
            block = build_finding_block(finding, st, W, i)
            # Keep first few items together to avoid orphaned headers
            story.append(KeepTogether(block[:4]))
            for item in block[4:]:
                story.append(item)
            story.append(HRFlowable(width=W, thickness=0.5, color=C_MID_GREY))

    story.append(PageBreak())

    # ══ RECON ══
    story += sec_header("5. RECONNAISSANCE RESULTS", st, W)
    subs = scan_data.get("subdomains",[])
    story.append(Paragraph(f"Subdomains Discovered ({len(subs)})",st["h2"]))
    if subs:
        sub_rows = [[Paragraph(h,st["label"]) for h in ["Subdomain","IPs","CNAME","Takeover Risk"]]]
        for s in subs[:80]:
            rc2 = SEV["HIGH"].hexval() if s.get("takeover_possible") else C_TEXT.hexval()
            sub_rows.append([
                Paragraph(esc(s.get("subdomain","")),st["code"]),
                Paragraph(esc(", ".join(s.get("ips",[]))),st["body"]),
                Paragraph(esc(s.get("cname","") or ""),st["body"]),
                Paragraph(f'<font color="{rc2}">{"⚠ YES" if s.get("takeover_possible") else "No"}</font>',st["body"]),
            ])
        subt = Table(sub_rows,colWidths=[65*mm,35*mm,45*mm,W-150*mm],repeatRows=1)
        subt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_NAVY),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LIGHT_GREY]),
            ("GRID",(0,0),(-1,-1),0.3,C_MID_GREY),
            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),("LEFTPADDING",(0,0),(-1,-1),5),
        ]))
        story.append(subt)
    ports = scan_data.get("open_ports",[])
    story.append(Spacer(1,8))
    story.append(Paragraph(f"Open Ports ({len(ports)})",st["h2"]))
    if ports:
        p_rows = [[Paragraph(h,st["label"]) for h in ["Port","Service","Banner (first 60 chars)","Risk"]]]
        for p in ports:
            rc3 = SEV["HIGH"].hexval() if p.get("risky") else SEV["LOW"].hexval()
            p_rows.append([
                Paragraph(f"{p['port']}/tcp",st["code"]),
                Paragraph(esc(p.get("service","?")),st["body"]),
                Paragraph(esc((p.get("banner","") or "")[:60]),st["code"]),
                Paragraph(f'<font color="{rc3}">{"HIGH" if p.get("risky") else "LOW"}</font>',st["body"]),
            ])
        pt = Table(p_rows,colWidths=[18*mm,28*mm,W-80*mm,20*mm],repeatRows=1)
        pt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_NAVY),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LIGHT_GREY]),
            ("GRID",(0,0),(-1,-1),0.3,C_MID_GREY),
            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),("LEFTPADDING",(0,0),(-1,-1),5),
        ]))
        story.append(pt)
    story.append(PageBreak())

    # ══ REMEDIATION ROADMAP ══
    story += sec_header("6. REMEDIATION ROADMAP", st, W)
    story.append(Paragraph(
        "Prioritised remediation guidance. Critical and High findings should be treated as emergencies. "
        "Medium findings should enter the next sprint cycle. Low findings should be tracked.",st["body"]))
    story.append(Spacer(1,8))
    timelines = {"CRITICAL":"24-72 hours","HIGH":"1-2 weeks","MEDIUM":"1 month","LOW":"Next quarter","INFO":"Ongoing"}
    for sev_name in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        sev_fs = [f for f in all_findings if f.get("severity")==sev_name]
        if not sev_fs: continue
        story.append(Paragraph(
            f'<font color="{SEV[sev_name].hexval()}">{sev_name}</font> — {len(sev_fs)} finding(s) — Target resolution: {timelines[sev_name]}',
            ParagraphStyle("rh",fontSize=10,textColor=SEV[sev_name],fontName="Helvetica-Bold",spaceBefore=8,spaceAfter=4)))
        for f in sev_fs:
            story.append(Paragraph(f"• <b>{esc(f.get('type','?'))}:</b> {esc(f.get('remediation','See OWASP.'))}", st["body"]))
        story.append(Spacer(1,4))
    story.append(PageBreak())

    # ══ APPENDIX ══
    story += sec_header("7. APPENDIX — SCAN LOGS", st, W)
    logs = scan_data.get("terminal_logs",[])
    if logs:
        log_text = "\n".join(f'[{e.get("ts","")}] [{e.get("level","").upper()}] {esc(e.get("msg",""))}' for e in logs[:120])
        story.append(Paragraph(log_text.replace("\n","<br/>"),st["code"]))
    story.append(Spacer(1,10))
    story.append(Paragraph("Disclaimer",st["h2"]))
    story.append(Paragraph(
        "This report was generated for authorised security testing purposes only. All testing was conducted "
        "within the agreed engagement scope with explicit written authorisation. Findings are provided to assist "
        "the client in improving its security posture. This document is CONFIDENTIAL and must be distributed "
        "only to authorised personnel on a need-to-know basis. The tester assumes no liability for damages "
        "resulting from misuse of the information contained herein.",st["disclaimer"]))

    # ── Build ──
    def make_canvas(filename, **kwargs):
        kwargs.pop("pagesize",None)
        return ReportCanvas(filename, pagesize=A4, meta=meta)

    doc.build(story, canvasmaker=make_canvas)
    return output_path
