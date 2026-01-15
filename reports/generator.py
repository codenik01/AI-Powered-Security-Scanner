from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import json
from datetime import datetime
import os
from typing import Dict, Any
import asyncio

class ReportGenerator:
    def __init__(self):
        self.reports_dir = "reports_storage"
        os.makedirs(self.reports_dir, exist_ok=True)
    
    async def generate_pdf(self, results: Dict[str, Any], scan_id: str) -> bytes:
        """Generate professional PDF report"""
        buffer = io.BytesIO()
        
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        story.append(Paragraph("AI-Powered Security Scan Report", title_style))
        story.append(Spacer(1, 12))
        
        # Summary Table
        summary_data = [
            ['Metric', 'Value'],
            ['Target', results['target']],
            ['Scan Date', results['scan_date']],
            ['Total Issues', str(results['summary']['total_vulnerabilities'])],
            ['Risk Level', results['summary']['risk_level']],
            ['Severity Score', str(results['summary']['severity_score'])]
        ]
        
        table = Table(summary_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Vulnerabilities by Severity
        severity_style = ParagraphStyle('Severity', fontSize=16, spaceAfter=12)
        story.append(Paragraph("Vulnerabilities by Severity", severity_style))
        
        sev_data = [['Severity', 'Count', 'Score']]
        for sev, count in results['summary']['by_severity'].items():
            sev_data.append([sev, str(count), ''])
        
        sev_table = Table(sev_data)
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkred),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (0,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 14),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 20))
        
        # Detailed Findings
        findings_style = ParagraphStyle('Findings', fontSize=16, spaceAfter=12)
        story.append(Paragraph("Detailed Findings", findings_style))
        
        for vuln in results['vulnerabilities'][:20]:  # Top 20
            vuln_para = f"<b>{vuln['type']} ({vuln['severity']})</b><br/>"
            vuln_para += f"{vuln['description']}<br/><br/>"
            
            if 'endpoint' in vuln:
                vuln_para += f"<i>Endpoint: {vuln['endpoint']}</i><br/>"
            
            if 'fix' in vuln:
                vuln_para += f"<b>Fix:</b> {vuln['fix']}<br/>"
            
            story.append(Paragraph(vuln_para))
            story.append(Spacer(1, 12))
        
        doc.build(story)
        buffer.seek(0)
        
        # Save for later retrieval
        filepath = os.path.join(self.reports_dir, f"{scan_id}.pdf")
        with open(filepath, 'wb') as f:
            f.write(buffer.getvalue())
        
        return buffer.getvalue()
    
    async def get_pdf(self, scan_id: str) -> bytes:
        filepath = os.path.join(self.reports_dir, f"{scan_id}.pdf")
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                return f.read()
        raise FileNotFoundError(f"Report {scan_id} not found")
    
    async def get_json(self, scan_id: str):
        # Save JSON report
        filepath = os.path.join(self.reports_dir, f"{scan_id}.json")
        # In production, you'd load from DB or cache
        sample_data = {"scan_id": scan_id, "status": "Report generated"}
        json_bytes = json.dumps(sample_data).encode()
        
        with open(filepath, 'wb') as f:
            f.write(json_bytes)
        
        return json_bytes