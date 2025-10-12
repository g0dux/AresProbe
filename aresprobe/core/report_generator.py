"""
AresProbe Report Generator
Advanced reporting system with multiple output formats and visualizations
"""

import os
import json
import html
import csv
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import base64
import hashlib
import webbrowser
import tempfile

from .logger import Logger


class ReportFormat(Enum):
    """Supported report formats"""
    HTML = "html"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    PDF = "pdf"
    TXT = "txt"
    MARKDOWN = "md"


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Vulnerability data structure"""
    id: str
    name: str
    description: str
    severity: SeverityLevel
    confidence: float
    url: str
    parameter: str
    payload: str
    response: str
    recommendation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class ScanSummary:
    """Scan summary data"""
    target_url: str
    scan_start: datetime
    scan_end: datetime
    duration: float
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    scan_types: List[str]
    status: str


class ReportGenerator:
    """
    Advanced report generator for AresProbe
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.template_dir = "aresprobe/templates"
        self.output_dir = "reports"
        self._ensure_directories()
        
        # Report configuration
        self.config = {
            'company_name': 'AresProbe Security',
            'company_logo': None,
            'include_screenshots': True,
            'include_recommendations': True,
            'include_technical_details': True,
            'color_scheme': 'dark',
            'language': 'en'
        }
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        os.makedirs(self.template_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_report(self, scan_results: Dict[str, Any], 
                       output_format: ReportFormat = ReportFormat.HTML,
                       output_file: str = None) -> str:
        """Generate security report in specified format"""
        try:
            # Parse scan results
            vulnerabilities = self._parse_vulnerabilities(scan_results)
            summary = self._create_scan_summary(scan_results, vulnerabilities)
            
            # Generate report based on format
            if output_format == ReportFormat.HTML:
                return self._generate_html_report(vulnerabilities, summary, output_file)
            elif output_format == ReportFormat.JSON:
                return self._generate_json_report(vulnerabilities, summary, output_file)
            elif output_format == ReportFormat.XML:
                return self._generate_xml_report(vulnerabilities, summary, output_file)
            elif output_format == ReportFormat.CSV:
                return self._generate_csv_report(vulnerabilities, summary, output_file)
            elif output_format == ReportFormat.TXT:
                return self._generate_txt_report(vulnerabilities, summary, output_file)
            elif output_format == ReportFormat.MARKDOWN:
                return self._generate_markdown_report(vulnerabilities, summary, output_file)
            else:
                raise ValueError(f"Unsupported report format: {output_format}")
                
        except Exception as e:
            self.logger.error(f"[-] Error generating report: {e}")
            raise
    
    def _parse_vulnerabilities(self, scan_results: Dict[str, Any]) -> List[Vulnerability]:
        """Parse vulnerabilities from scan results"""
        vulnerabilities = []
        vuln_id = 1
        
        try:
            results = scan_results.get('results', {})
            
            for scan_type, scan_data in results.items():
                if isinstance(scan_data, dict) and 'vulnerabilities' in scan_data:
                    for vuln_data in scan_data['vulnerabilities']:
                        vulnerability = Vulnerability(
                            id=f"ARES-{vuln_id:04d}",
                            name=vuln_data.get('vuln_type', 'Unknown'),
                            description=vuln_data.get('description', 'No description available'),
                            severity=self._map_severity(vuln_data.get('severity', 'medium')),
                            confidence=vuln_data.get('confidence', 0.0),
                            url=scan_data.get('target', 'Unknown'),
                            parameter=vuln_data.get('parameter', 'Unknown'),
                            payload=vuln_data.get('payload', ''),
                            response=vuln_data.get('response', ''),
                            recommendation=self._get_recommendation(vuln_data.get('vuln_type', '')),
                            cwe_id=self._get_cwe_id(vuln_data.get('vuln_type', '')),
                            owasp_category=self._get_owasp_category(vuln_data.get('vuln_type', ''))
                        )
                        vulnerabilities.append(vulnerability)
                        vuln_id += 1
        
        except Exception as e:
            self.logger.error(f"[-] Error parsing vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _create_scan_summary(self, scan_results: Dict[str, Any], 
                           vulnerabilities: List[Vulnerability]) -> ScanSummary:
        """Create scan summary from results"""
        # Count vulnerabilities by severity
        severity_counts = {level: 0 for level in SeverityLevel}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        return ScanSummary(
            target_url=scan_results.get('target', 'Unknown'),
            scan_start=datetime.fromtimestamp(scan_results.get('start_time', 0)),
            scan_end=datetime.fromtimestamp(scan_results.get('end_time', 0)),
            duration=scan_results.get('duration', 0),
            total_vulnerabilities=len(vulnerabilities),
            critical_count=severity_counts[SeverityLevel.CRITICAL],
            high_count=severity_counts[SeverityLevel.HIGH],
            medium_count=severity_counts[SeverityLevel.MEDIUM],
            low_count=severity_counts[SeverityLevel.LOW],
            info_count=severity_counts[SeverityLevel.INFO],
            scan_types=scan_results.get('scan_types', []),
            status=scan_results.get('status', 'Unknown')
        )
    
    def _generate_html_report(self, vulnerabilities: List[Vulnerability], 
                            summary: ScanSummary, output_file: str = None) -> str:
        """Generate HTML report"""
        if not output_file:
            output_file = os.path.join(self.output_dir, f"aresprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        html_content = self._get_html_template()
        
        # Replace placeholders
        html_content = html_content.replace('{{COMPANY_NAME}}', self.config['company_name'])
        html_content = html_content.replace('{{TARGET_URL}}', summary.target_url)
        html_content = html_content.replace('{{SCAN_DATE}}', summary.scan_start.strftime('%Y-%m-%d %H:%M:%S'))
        html_content = html_content.replace('{{DURATION}}', f"{summary.duration:.2f} seconds")
        html_content = html_content.replace('{{TOTAL_VULNS}}', str(summary.total_vulnerabilities))
        html_content = html_content.replace('{{CRITICAL_COUNT}}', str(summary.critical_count))
        html_content = html_content.replace('{{HIGH_COUNT}}', str(summary.high_count))
        html_content = html_content.replace('{{MEDIUM_COUNT}}', str(summary.medium_count))
        html_content = html_content.replace('{{LOW_COUNT}}', str(summary.low_count))
        html_content = html_content.replace('{{INFO_COUNT}}', str(summary.info_count))
        
        # Generate vulnerability table
        vuln_table = self._generate_vulnerability_table_html(vulnerabilities)
        html_content = html_content.replace('{{VULNERABILITY_TABLE}}', vuln_table)
        
        # Generate executive summary
        exec_summary = self._generate_executive_summary_html(summary, vulnerabilities)
        html_content = html_content.replace('{{EXECUTIVE_SUMMARY}}', exec_summary)
        
        # Write file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.success(f"[+] HTML report generated: {output_file}")
        return output_file
    
    def _generate_json_report(self, vulnerabilities: List[Vulnerability], 
                            summary: ScanSummary, output_file: str = None) -> str:
        """Generate JSON report"""
        if not output_file:
            output_file = os.path.join(self.output_dir, f"aresprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        report_data = {
            'summary': asdict(summary),
            'vulnerabilities': [asdict(vuln) for vuln in vulnerabilities],
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'generator': 'AresProbe Report Generator',
                'version': '2.0.0'
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        self.logger.success(f"[+] JSON report generated: {output_file}")
        return output_file
    
    def _generate_xml_report(self, vulnerabilities: List[Vulnerability], 
                           summary: ScanSummary, output_file: str = None) -> str:
        """Generate XML report"""
        if not output_file:
            output_file = os.path.join(self.output_dir, f"aresprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
        
        root = ET.Element('aresprobe_report')
        root.set('version', '2.0.0')
        root.set('generated_at', datetime.now().isoformat())
        
        # Summary
        summary_elem = ET.SubElement(root, 'summary')
        summary_elem.set('target_url', summary.target_url)
        summary_elem.set('scan_start', summary.scan_start.isoformat())
        summary_elem.set('scan_end', summary.scan_end.isoformat())
        summary_elem.set('duration', str(summary.duration))
        summary_elem.set('total_vulnerabilities', str(summary.total_vulnerabilities))
        summary_elem.set('critical_count', str(summary.critical_count))
        summary_elem.set('high_count', str(summary.high_count))
        summary_elem.set('medium_count', str(summary.medium_count))
        summary_elem.set('low_count', str(summary.low_count))
        summary_elem.set('info_count', str(summary.info_count))
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, 'vulnerabilities')
        for vuln in vulnerabilities:
            vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
            vuln_elem.set('id', vuln.id)
            vuln_elem.set('name', vuln.name)
            vuln_elem.set('severity', vuln.severity.value)
            vuln_elem.set('confidence', str(vuln.confidence))
            vuln_elem.set('url', vuln.url)
            vuln_elem.set('parameter', vuln.parameter)
            
            desc_elem = ET.SubElement(vuln_elem, 'description')
            desc_elem.text = vuln.description
            
            payload_elem = ET.SubElement(vuln_elem, 'payload')
            payload_elem.text = vuln.payload
            
            recommendation_elem = ET.SubElement(vuln_elem, 'recommendation')
            recommendation_elem.text = vuln.recommendation
        
        # Write file
        tree = ET.ElementTree(root)
        tree.write(output_file, encoding='utf-8', xml_declaration=True)
        
        self.logger.success(f"[+] XML report generated: {output_file}")
        return output_file
    
    def _generate_csv_report(self, vulnerabilities: List[Vulnerability], 
                           summary: ScanSummary, output_file: str = None) -> str:
        """Generate CSV report"""
        if not output_file:
            output_file = os.path.join(self.output_dir, f"aresprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'ID', 'Name', 'Description', 'Severity', 'Confidence', 
                'URL', 'Parameter', 'Payload', 'Recommendation', 'CWE ID', 'OWASP Category'
            ])
            
            # Write vulnerabilities
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.id, vuln.name, vuln.description, vuln.severity.value,
                    vuln.confidence, vuln.url, vuln.parameter, vuln.payload,
                    vuln.recommendation, vuln.cwe_id or '', vuln.owasp_category or ''
                ])
        
        self.logger.success(f"[+] CSV report generated: {output_file}")
        return output_file
    
    def _generate_txt_report(self, vulnerabilities: List[Vulnerability], 
                           summary: ScanSummary, output_file: str = None) -> str:
        """Generate text report"""
        if not output_file:
            output_file = os.path.join(self.output_dir, f"aresprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("ARESPROBE SECURITY SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary
            f.write("SCAN SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Target URL: {summary.target_url}\n")
            f.write(f"Scan Date: {summary.scan_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {summary.duration:.2f} seconds\n")
            f.write(f"Status: {summary.status}\n\n")
            
            f.write("VULNERABILITY SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Vulnerabilities: {summary.total_vulnerabilities}\n")
            f.write(f"Critical: {summary.critical_count}\n")
            f.write(f"High: {summary.high_count}\n")
            f.write(f"Medium: {summary.medium_count}\n")
            f.write(f"Low: {summary.low_count}\n")
            f.write(f"Info: {summary.info_count}\n\n")
            
            # Vulnerabilities
            f.write("VULNERABILITIES\n")
            f.write("-" * 40 + "\n")
            for i, vuln in enumerate(vulnerabilities, 1):
                f.write(f"\n{i}. {vuln.name} ({vuln.severity.value.upper()})\n")
                f.write(f"   ID: {vuln.id}\n")
                f.write(f"   URL: {vuln.url}\n")
                f.write(f"   Parameter: {vuln.parameter}\n")
                f.write(f"   Description: {vuln.description}\n")
                f.write(f"   Payload: {vuln.payload}\n")
                f.write(f"   Recommendation: {vuln.recommendation}\n")
                if vuln.cwe_id:
                    f.write(f"   CWE ID: {vuln.cwe_id}\n")
                if vuln.owasp_category:
                    f.write(f"   OWASP Category: {vuln.owasp_category}\n")
        
        self.logger.success(f"[+] Text report generated: {output_file}")
        return output_file
    
    def _generate_markdown_report(self, vulnerabilities: List[Vulnerability], 
                                summary: ScanSummary, output_file: str = None) -> str:
        """Generate Markdown report"""
        if not output_file:
            output_file = os.path.join(self.output_dir, f"aresprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# AresProbe Security Scan Report\n\n")
            
            # Summary
            f.write("## Scan Summary\n\n")
            f.write(f"- **Target URL:** {summary.target_url}\n")
            f.write(f"- **Scan Date:** {summary.scan_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- **Duration:** {summary.duration:.2f} seconds\n")
            f.write(f"- **Status:** {summary.status}\n\n")
            
            # Vulnerability counts
            f.write("## Vulnerability Summary\n\n")
            f.write("| Severity | Count |\n")
            f.write("|----------|-------|\n")
            f.write(f"| Critical | {summary.critical_count} |\n")
            f.write(f"| High | {summary.high_count} |\n")
            f.write(f"| Medium | {summary.medium_count} |\n")
            f.write(f"| Low | {summary.low_count} |\n")
            f.write(f"| Info | {summary.info_count} |\n")
            f.write(f"| **Total** | **{summary.total_vulnerabilities}** |\n\n")
            
            # Vulnerabilities
            f.write("## Vulnerabilities\n\n")
            for i, vuln in enumerate(vulnerabilities, 1):
                f.write(f"### {i}. {vuln.name} ({vuln.severity.value.upper()})\n\n")
                f.write(f"**ID:** {vuln.id}\n\n")
                f.write(f"**URL:** {vuln.url}\n\n")
                f.write(f"**Parameter:** {vuln.parameter}\n\n")
                f.write(f"**Description:** {vuln.description}\n\n")
                f.write(f"**Payload:**\n```\n{vuln.payload}\n```\n\n")
                f.write(f"**Recommendation:** {vuln.recommendation}\n\n")
                if vuln.cwe_id:
                    f.write(f"**CWE ID:** {vuln.cwe_id}\n\n")
                if vuln.owasp_category:
                    f.write(f"**OWASP Category:** {vuln.owasp_category}\n\n")
                f.write("---\n\n")
        
        self.logger.success(f"[+] Markdown report generated: {output_file}")
        return output_file
    
    def _get_html_template(self) -> str:
        """Get HTML report template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AresProbe Security Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #1a1a1a;
            color: #ffffff;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }
        .summary {
            background: #2d2d2d;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            border-left: 5px solid #ff6b6b;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: #3d3d3d;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #555;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #ff6b6b;
        }
        .vulnerability-table {
            background: #2d2d2d;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 30px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #555;
        }
        th {
            background: #3d3d3d;
            font-weight: bold;
            color: #ff6b6b;
        }
        .severity-critical { color: #ff4757; font-weight: bold; }
        .severity-high { color: #ff6b6b; font-weight: bold; }
        .severity-medium { color: #ffa502; font-weight: bold; }
        .severity-low { color: #2ed573; font-weight: bold; }
        .severity-info { color: #70a1ff; font-weight: bold; }
        .code {
            background: #1a1a1a;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            border: 1px solid #555;
            overflow-x: auto;
        }
        .recommendation {
            background: #2d2d2d;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #2ed573;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AresProbe Security Report</h1>
        <p>Advanced Web Security Testing Framework</p>
    </div>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Target:</strong> {{TARGET_URL}}</p>
        <p><strong>Scan Date:</strong> {{SCAN_DATE}}</p>
        <p><strong>Duration:</strong> {{DURATION}}</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{{TOTAL_VULNS}}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number severity-critical">{{CRITICAL_COUNT}}</div>
                <div>Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-number severity-high">{{HIGH_COUNT}}</div>
                <div>High</div>
            </div>
            <div class="stat-card">
                <div class="stat-number severity-medium">{{MEDIUM_COUNT}}</div>
                <div>Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-number severity-low">{{LOW_COUNT}}</div>
                <div>Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-number severity-info">{{INFO_COUNT}}</div>
                <div>Info</div>
            </div>
        </div>
    </div>
    
    {{EXECUTIVE_SUMMARY}}
    
    <div class="vulnerability-table">
        <h2 style="padding: 20px; margin: 0;">🔍 Detailed Vulnerabilities</h2>
        {{VULNERABILITY_TABLE}}
    </div>
</body>
</html>
        """
    
    def _generate_vulnerability_table_html(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate HTML table for vulnerabilities"""
        if not vulnerabilities:
            return "<p style='padding: 20px;'>No vulnerabilities found.</p>"
        
        html = "<table><tr><th>ID</th><th>Name</th><th>Severity</th><th>URL</th><th>Parameter</th><th>Actions</th></tr>"
        
        for vuln in vulnerabilities:
            severity_class = f"severity-{vuln.severity.value}"
            html += f"""
            <tr>
                <td>{vuln.id}</td>
                <td>{html.escape(vuln.name)}</td>
                <td class="{severity_class}">{vuln.severity.value.upper()}</td>
                <td>{html.escape(vuln.url)}</td>
                <td>{html.escape(vuln.parameter)}</td>
                <td>
                    <button onclick="toggleDetails('{vuln.id}')">View Details</button>
                </td>
            </tr>
            <tr id="details-{vuln.id}" style="display: none;">
                <td colspan="6">
                    <div style="padding: 20px; background: #3d3d3d; margin: 10px 0; border-radius: 5px;">
                        <h4>Description</h4>
                        <p>{html.escape(vuln.description)}</p>
                        
                        <h4>Payload</h4>
                        <div class="code">{html.escape(vuln.payload)}</div>
                        
                        <div class="recommendation">
                            <h4>Recommendation</h4>
                            <p>{html.escape(vuln.recommendation)}</p>
                        </div>
                        
                        {f'<p><strong>CWE ID:</strong> {vuln.cwe_id}</p>' if vuln.cwe_id else ''}
                        {f'<p><strong>OWASP Category:</strong> {vuln.owasp_category}</p>' if vuln.owasp_category else ''}
                    </div>
                </td>
            </tr>
            """
        
        html += "</table>"
        html += """
        <script>
        function toggleDetails(vulnId) {
            const details = document.getElementById('details-' + vulnId);
            details.style.display = details.style.display === 'none' ? 'table-row' : 'none';
        }
        </script>
        """
        
        return html
    
    def _generate_executive_summary_html(self, summary: ScanSummary, 
                                       vulnerabilities: List[Vulnerability]) -> str:
        """Generate executive summary HTML"""
        risk_level = "HIGH" if summary.critical_count > 0 or summary.high_count > 2 else "MEDIUM" if summary.high_count > 0 else "LOW"
        
        return f"""
        <div class="summary">
            <h2>📋 Executive Summary</h2>
            <p><strong>Overall Risk Level:</strong> <span class="severity-{risk_level.lower()}">{risk_level}</span></p>
            <p>This security assessment identified {summary.total_vulnerabilities} vulnerabilities across the target application. 
            {'Immediate attention is required for critical and high-severity issues.' if summary.critical_count > 0 or summary.high_count > 0 else 'The application shows good security posture with only minor issues identified.'}</p>
        </div>
        """
    
    def _map_severity(self, severity: str) -> SeverityLevel:
        """Map severity string to enum"""
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO
        }
        return severity_map.get(severity.lower(), SeverityLevel.MEDIUM)
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for vulnerability type"""
        recommendations = {
            'sql_injection': 'Implement parameterized queries, input validation, and use a Web Application Firewall (WAF).',
            'xss': 'Implement Content Security Policy (CSP), output encoding, and input validation.',
            'directory_traversal': 'Implement proper input validation and use whitelist-based file access.',
            'command_injection': 'Avoid executing system commands with user input and implement proper input validation.',
            'xxe': 'Disable XML external entity processing and use safe XML parsers.',
            'ssrf': 'Implement proper input validation and restrict outbound connections.'
        }
        return recommendations.get(vuln_type, 'Implement proper input validation and security controls.')
    
    def _get_cwe_id(self, vuln_type: str) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_map = {
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79',
            'directory_traversal': 'CWE-22',
            'command_injection': 'CWE-78',
            'xxe': 'CWE-611',
            'ssrf': 'CWE-918'
        }
        return cwe_map.get(vuln_type, '')
    
    def _get_owasp_category(self, vuln_type: str) -> str:
        """Get OWASP category for vulnerability type"""
        owasp_map = {
            'sql_injection': 'A03:2021 - Injection',
            'xss': 'A03:2021 - Injection',
            'directory_traversal': 'A01:2021 - Broken Access Control',
            'command_injection': 'A03:2021 - Injection',
            'xxe': 'A05:2021 - Security Misconfiguration',
            'ssrf': 'A10:2021 - Server-Side Request Forgery'
        }
        return owasp_map.get(vuln_type, '')
    
    def open_report(self, report_path: str):
        """Open report in default application"""
        try:
            if report_path.endswith('.html'):
                webbrowser.open(f'file://{os.path.abspath(report_path)}')
            else:
                os.startfile(report_path) if os.name == 'nt' else os.system(f'xdg-open "{report_path}"')
            self.logger.success(f"[+] Report opened: {report_path}")
        except Exception as e:
            self.logger.error(f"[-] Error opening report: {e}")
    
    def get_report_summary(self, report_path: str) -> Dict[str, Any]:
        """Get summary information from a report file"""
        try:
            if report_path.endswith('.json'):
                with open(report_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('summary', {})
            else:
                # For other formats, return basic file info
                stat = os.stat(report_path)
                return {
                    'file_size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                }
        except Exception as e:
            self.logger.error(f"[-] Error reading report summary: {e}")
            return {}
