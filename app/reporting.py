"""Self-contained local HTML and PDF investigation reports."""
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import html
import io
import json


BAND_COLORS = {
    "Critical": ("#991b1b", "#fee2e2"),
    "High": ("#c2410c", "#ffedd5"),
    "Elevated": ("#a16207", "#fef9c3"),
    "Low": ("#166534", "#dcfce7"),
    "Needs review": ("#1d4ed8", "#dbeafe"),
}


def html_report(result: dict) -> bytes:
    esc = lambda x: html.escape(str(x))
    band = str(result.get("risk_band", "Needs review"))
    foreground, background = BAND_COLORS.get(band, BAND_COLORS["Needs review"])
    evidence = result.get("evidence_input", {}) if isinstance(result.get("evidence_input"), dict) else {}
    message = evidence.get("message", result.get("normalization", {}).get("original", ""))
    source_url = evidence.get("source_url", "")
    findings = "".join(f"<tr><td>{esc(f.get('severity',''))}</td><td>{esc(f.get('title',''))}</td><td>{esc(f.get('evidence',''))}</td></tr>" for f in result.get("findings", [])) or "<tr><td colspan='3'>No rule finding</td></tr>"
    timeline = "".join(f"<li>Message {esc(x.get('message'))} - {esc(', '.join(x.get('stages',[])))}: {esc(x.get('excerpt',''))}</li>" for x in result.get("conversation", {}).get("timeline", [])) or "<li>No staged pattern detected</li>"
    urls = "".join(f"<li>{esc(x.get('host',''))}: {esc('; '.join(x.get('signals',[])) or 'No URL signal')}</li>" for x in result.get("url_analysis", [])) or "<li>No URL supplied</li>"
    actions = "".join(f"<li>{esc(x)}</li>" for x in result.get("recommended_actions", []))
    source = json.dumps(result, ensure_ascii=False, indent=2).replace("</", "<\\/")
    doc = f"""<!doctype html><html><head><meta charset='utf-8'><title>NexVision investigation report</title><style>
    body{{font:15px system-ui,sans-serif;margin:40px;color:#172134;max-width:1000px}}h1{{color:#12284a}}.band{{display:inline-block;padding:7px 12px;border-radius:8px;color:{foreground};background:{background};border:1px solid {foreground};font-weight:700}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd4df;padding:8px;text-align:left;vertical-align:top}}code,pre{{word-break:break-word;white-space:pre-wrap}}pre{{background:#f8fafc;border:1px solid #ccd4df;padding:12px}}.note{{background:#edf5ff;padding:12px;border-left:4px solid #2463a7}}.legend span{{display:inline-block;margin:2px 6px 2px 0;padding:3px 6px;border-radius:5px}}footer{{margin-top:30px;color:#536174;font-size:12px}}</style></head><body>
    <h1>NexVision OSINT Investigation Report</h1><p>Generated {esc(result.get('generated_at',''))}</p><p class='band'>{esc(band)} - {esc(result.get('risk_score'))}/100</p><p>{esc(result.get('summary'))}</p>
    <p class='legend'><span style='background:#fee2e2;color:#991b1b'>Critical</span><span style='background:#ffedd5;color:#c2410c'>High</span><span style='background:#fef9c3;color:#a16207'>Elevated</span><span style='background:#dcfce7;color:#166534'>Low</span><span style='background:#dbeafe;color:#1d4ed8'>Needs review</span></p>
    <h2>Submitted evidence</h2><p><strong>Source link:</strong> <code>{esc(source_url or 'Not supplied')}</code></p><pre>{esc(message or 'No message text supplied')}</pre>
    <h2>Detected evidence</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence excerpt</th></tr></thead><tbody>{findings}</tbody></table>
    <h2>Conversation sequence</h2><p>{esc(result.get('conversation',{}).get('pattern',''))}</p><ol>{timeline}</ol><h2>Domain and identity</h2><ul>{urls}</ul>
    <h2>Recommended actions</h2><ul>{actions}</ul><h2>Method and limitations</h2><p class='note'>{esc(result.get('privacy',''))} Risk bands are decision-support labels, not proof or population fraud probabilities.</p>
    <p>Input SHA-256: <code>{esc(result.get('input_sha256',''))}</code></p><footer>Generated locally by NexVision v{esc(result.get('version',''))}. Preserve the original evidence separately.</footer>
    <script type='application/json' id='analysis-data'>{source}</script></body></html>"""
    return doc.encode("utf-8")


def pdf_report(result: dict) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
    except ImportError as exc: raise RuntimeError("PDF export requires the local reportlab package") from exc
    buffer = io.BytesIO(); styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallNV", parent=styles["BodyText"], fontSize=8.5, leading=11))
    def p(value, style="BodyText"): return Paragraph(html.escape(str(value)), styles[style])
    band = str(result.get("risk_band", "Needs review")); foreground, background = BAND_COLORS.get(band, BAND_COLORS["Needs review"])
    evidence = result.get("evidence_input", {}) if isinstance(result.get("evidence_input"), dict) else {}
    message = str(evidence.get("message", result.get("normalization", {}).get("original", "")))
    source_url = str(evidence.get("source_url", ""))
    band_table = Table([[p(f"{band} - {result.get('risk_score',0)}/100", "Heading1")]], colWidths=[179*mm])
    band_table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), colors.HexColor(background)), ("TEXTCOLOR", (0,0), (-1,-1), colors.HexColor(foreground)), ("BOX", (0,0), (-1,-1), 1, colors.HexColor(foreground)), ("LEFTPADDING", (0,0), (-1,-1), 8), ("RIGHTPADDING", (0,0), (-1,-1), 8)]))
    displayed = message[:20_000] + ("\n[truncated in PDF; HTML/JSON retains the complete input]" if len(message) > 20_000 else "")
    story = [p("NexVision OSINT Investigation Report", "Title"), p(f"Generated {result.get('generated_at','')}", "SmallNV"), Spacer(1, 6*mm), band_table, p(result.get("summary", "")), Spacer(1, 4*mm), p("Submitted evidence", "Heading2"), p("Source link: " + (source_url or "Not supplied"), "SmallNV"), Preformatted(html.escape(displayed or "No message text supplied"), styles["SmallNV"]), Spacer(1, 4*mm), p("Detected evidence", "Heading2")]
    rows = [[p("Severity", "SmallNV"), p("Finding", "SmallNV"), p("Evidence excerpt", "SmallNV")]]
    for finding in result.get("findings", [])[:25]: rows.append([p(finding.get("severity", ""), "SmallNV"), p(finding.get("title", ""), "SmallNV"), p(finding.get("evidence", ""), "SmallNV")])
    if len(rows) == 1: rows.append([p("-", "SmallNV"), p("No rule finding", "SmallNV"), p("-", "SmallNV")])
    table = Table(rows, colWidths=[22*mm, 52*mm, 105*mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#173a64")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#aab4c2")), ("VALIGN", (0,0), (-1,-1), "TOP"), ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5), ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4)])); story += [table, Spacer(1, 5*mm), p("Conversation sequence", "Heading2"), p(result.get("conversation", {}).get("pattern", "No staged pattern detected"))]
    for item in result.get("conversation", {}).get("timeline", [])[:20]: story.append(p(f"Message {item.get('message')} - {', '.join(item.get('stages', []))}: {item.get('excerpt','')}", "SmallNV"))
    story += [Spacer(1, 5*mm), p("Recommended actions", "Heading2")]
    for action in result.get("recommended_actions", []): story.append(p("- " + action))
    story += [Spacer(1, 5*mm), p("Method and limitations", "Heading2"), p(result.get("privacy", "")), p("Risk bands are decision-support labels, not proof or population fraud probabilities."), Spacer(1, 3*mm), p("Input SHA-256: " + result.get("input_sha256", ""), "SmallNV")]
    def footer(canvas, doc):
        canvas.saveState(); canvas.setFont("Helvetica", 8); canvas.setFillColor(colors.HexColor("#536174")); canvas.drawString(18*mm, 12*mm, f"NexVision v{result.get('version','')}"); canvas.drawRightString(192*mm, 12*mm, f"Page {doc.page}"); canvas.restoreState()
    SimpleDocTemplate(buffer, pagesize=A4, rightMargin=15*mm, leftMargin=15*mm, topMargin=16*mm, bottomMargin=18*mm, title="NexVision OSINT Investigation Report", author="NexVision local checker").build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
