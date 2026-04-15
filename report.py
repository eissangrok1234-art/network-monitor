from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_report(devices, alerts):
    doc = SimpleDocTemplate("network_report.pdf")
    styles = getSampleStyleSheet()

    content = []

    content.append(Paragraph("Network Security Report", styles['Title']))
    content.append(Spacer(1, 10))

    content.append(Paragraph(f"Total Devices: {len(devices)}", styles['Normal']))
    content.append(Spacer(1, 10))

    content.append(Paragraph("Alerts:", styles['Heading2']))

    for alert in alerts:
        content.append(Paragraph(alert, styles['Normal']))

    doc.build(content)