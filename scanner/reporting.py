import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from scanner.models import ScanResult

def generate_pdf_report(scan_result: ScanResult, output_path: str = "report.pdf"):
    """
    Generates a PDF report for the scan results.
    """
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = styles['Heading1']
    title_style.alignment = 1 # Center
    
    subtitle_style = styles['Heading2']
    vuln_style = styles['Heading3']
    
    normal_style = styles['Normal']
    
    elements = []
    
    # Title
    elements.append(Paragraph("HackBuddy Vulnerability Scan Report", title_style))
    elements.append(Spacer(1, 12))
    
    # Summary
    elements.append(Paragraph(f"Target URL: {scan_result.target_url}", subtitle_style))
    elements.append(Paragraph(f"Total Findings: {len(scan_result.findings)}", normal_style))
    elements.append(Spacer(1, 12))
    
    if not scan_result.findings:
        elements.append(Paragraph("No vulnerabilities detected during the scan.", normal_style))
    else:
        # Findings
        for finding in scan_result.findings:
            
            # Color code severity
            color_hex = "#333333"
            if finding.severity == "Critical":
                color_hex = "#ff0000"
            elif finding.severity == "High":
                color_hex = "#ff9900"
            elif finding.severity == "Medium":
                color_hex = "#ffff00"
            elif finding.severity == "Low":
                color_hex = "#00ff00"
                
            sev_style = ParagraphStyle('Severity', parent=styles['Normal'], textColor=color_hex, fontName='Helvetica-Bold')
            
            elements.append(Paragraph(f"{finding.vuln_type}", vuln_style))
            elements.append(Paragraph(f"Severity: {finding.severity}", sev_style))
            elements.append(Paragraph(f"Path/Resource: {finding.path}", normal_style))
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(f"Description: {finding.description}", normal_style))
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(f"Remediation: {finding.remediation}", normal_style))
            elements.append(Spacer(1, 24))

    doc.build(elements)
    return output_path
