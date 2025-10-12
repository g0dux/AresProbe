"""
AresProbe Web Dashboard
Advanced web interface for security monitoring and compliance checking
"""

import asyncio
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn
import sqlite3
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import pandas as pd
import plotly.graph_objs as go
import plotly.utils

from ..core.logger import Logger
from ..core.engine import AresEngine
from ..core.compliance_checker import ComplianceChecker
from ..core.post_exploitation import PostExploitationEngine
from ..core.zero_day_detector import ZeroDayDetector
from ..core.payload_generator import PayloadGenerator
from ..core.fuzzing_engine import FuzzingEngine
from ..core.crypto_analyzer import CryptographicAnalyzer
from ..core.network_protocol_analyzer import NetworkProtocolAnalyzer

# Database setup
Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)
    vulnerability_type = Column(String)
    severity = Column(String)
    description = Column(Text)
    payload = Column(Text)
    response = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    compliance_violation = Column(Boolean, default=False)
    owasp_category = Column(String)
    pci_violation = Column(Boolean, default=False)
    gdpr_violation = Column(Boolean, default=False)
    sox_violation = Column(Boolean, default=False)

class ComplianceResult(Base):
    __tablename__ = "compliance_results"
    
    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False)
    framework = Column(String, nullable=False)
    check_name = Column(String, nullable=False)
    status = Column(String, nullable=False)  # PASS, FAIL, WARNING
    description = Column(Text)
    recommendation = Column(Text)
    severity = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class PostExploitationResult(Base):
    __tablename__ = "post_exploitation_results"
    
    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False)
    technique = Column(String, nullable=False)
    success = Column(Boolean, default=False)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

class ZeroDayResult(Base):
    __tablename__ = "zero_day_results"
    
    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False)
    vulnerability_type = Column(String, nullable=False)
    confidence = Column(Float)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Pydantic models
class ScanRequest(BaseModel):
    target: str
    scan_type: str
    options: Dict[str, Any] = {}

class ComplianceRequest(BaseModel):
    target: str
    frameworks: List[str] = ["OWASP", "PCI", "GDPR", "SOX"]

class PostExploitationRequest(BaseModel):
    target: str
    techniques: List[str] = []

class DashboardStats(BaseModel):
    total_scans: int
    vulnerabilities_found: int
    compliance_violations: int
    zero_day_detections: int
    post_exploitation_success: int

class WebDashboard:
    """Advanced Web Dashboard for AresProbe"""
    
    def __init__(self, engine: AresEngine, logger: Logger):
        self.engine = engine
        self.logger = logger
        self.app = FastAPI(title="AresProbe Dashboard", version="2.0")
        self.connected_clients: List[WebSocket] = []
        
        # Initialize advanced engines
        self.compliance_checker = ComplianceChecker(self.logger)
        self.post_exploitation = PostExploitationEngine(self.logger)
        self.zero_day_detector = ZeroDayDetector(self.logger)
        self.payload_generator = PayloadGenerator(self.logger)
        self.fuzzing_engine = FuzzingEngine(self.logger)
        self.crypto_analyzer = CryptographicAnalyzer(self.logger)
        self.network_protocol_analyzer = NetworkProtocolAnalyzer(self.logger)
        
        # Database setup
        self.db_path = "dashboard.db"
        self.engine_db = create_engine(f"sqlite:///{self.db_path}")
        Base.metadata.create_all(self.engine_db)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine_db)
        self.db_session = SessionLocal()
        
        # Setup routes
        self._setup_routes()
        
    def _setup_routes(self):
        """Setup all dashboard routes"""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request):
            return self._get_dashboard_html()
        
        @self.app.get("/api/stats")
        async def get_stats():
            return await self._get_dashboard_stats()
        
        @self.app.get("/api/scans")
        async def get_scans():
            return await self._get_scan_results()
        
        @self.app.get("/api/compliance")
        async def get_compliance():
            return await self._get_compliance_results()
        
        @self.app.get("/api/post-exploitation")
        async def get_post_exploitation():
            return await self._get_post_exploitation_results()
        
        @self.app.get("/api/zero-day")
        async def get_zero_day():
            return await self._get_zero_day_results()
        
        @self.app.post("/api/scan")
        async def start_scan(request: ScanRequest):
            return await self._start_scan(request)
        
        @self.app.post("/api/compliance-check")
        async def compliance_check(request: ComplianceRequest):
            return await self._compliance_check(request)
        
        @self.app.post("/api/post-exploitation")
        async def post_exploitation(request: PostExploitationRequest):
            return await self._post_exploitation(request)
        
        @self.app.get("/api/charts/vulnerabilities")
        async def get_vulnerability_chart():
            return await self._get_vulnerability_chart()
        
        @self.app.get("/api/charts/compliance")
        async def get_compliance_chart():
            return await self._get_compliance_chart()
        
        @self.app.get("/api/charts/timeline")
        async def get_timeline_chart():
            return await self._get_timeline_chart()
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await self._handle_websocket(websocket)
    
    def _get_dashboard_html(self) -> str:
        """Generate dashboard HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AresProbe Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            font-family: 'Courier New', monospace; 
            background: #000; 
            color: #00ff00; 
            margin: 0; 
            padding: 20px;
        }
        .header { 
            text-align: center; 
            margin-bottom: 30px; 
            border: 2px solid #00ff00; 
            padding: 20px;
        }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .stat-card { 
            border: 1px solid #00ff00; 
            padding: 15px; 
            text-align: center; 
        }
        .charts-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); 
            gap: 20px; 
        }
        .chart-container { 
            border: 1px solid #00ff00; 
            padding: 15px; 
            height: 400px; 
        }
        .controls { 
            margin-bottom: 20px; 
            padding: 15px; 
            border: 1px solid #00ff00; 
        }
        .btn { 
            background: #00ff00; 
            color: #000; 
            border: none; 
            padding: 10px 20px; 
            margin: 5px; 
            cursor: pointer; 
            font-family: 'Courier New', monospace;
        }
        .btn:hover { 
            background: #00cc00; 
        }
        .log-container { 
            border: 1px solid #00ff00; 
            padding: 15px; 
            height: 300px; 
            overflow-y: auto; 
            background: #001100; 
        }
        .log-entry { 
            margin: 5px 0; 
            padding: 5px; 
            border-left: 3px solid #00ff00; 
            padding-left: 10px; 
        }
        .critical { color: #ff0000; }
        .high { color: #ff6600; }
        .medium { color: #ffff00; }
        .low { color: #00ff00; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ARESPROBE DASHBOARD</h1>
        <p>Advanced Security Monitoring & Compliance Center</p>
    </div>
    
    <div class="controls">
        <h3>CONTROLS</h3>
        <button class="btn" onclick="startScan()">Start Scan</button>
        <button class="btn" onclick="checkCompliance()">Check Compliance</button>
        <button class="btn" onclick="postExploitation()">Post Exploitation</button>
        <button class="btn" onclick="zeroDayDetection()">Zero-Day Detection</button>
        <button class="btn" onclick="generatePayload()">Generate Payload</button>
        <button class="btn" onclick="startFuzzing()">Start Fuzzing</button>
        <button class="btn" onclick="cryptoAnalysis()">Crypto Analysis</button>
        <button class="btn" onclick="networkAnalysis()">Network Analysis</button>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Scans</h3>
            <div id="total-scans">0</div>
        </div>
        <div class="stat-card">
            <h3>Vulnerabilities</h3>
            <div id="vulnerabilities">0</div>
        </div>
        <div class="stat-card">
            <h3>Compliance Violations</h3>
            <div id="compliance-violations">0</div>
        </div>
        <div class="stat-card">
            <h3>Zero-Day Detections</h3>
            <div id="zero-day">0</div>
        </div>
        <div class="stat-card">
            <h3>Post-Exploitation Success</h3>
            <div id="post-exploitation">0</div>
        </div>
    </div>
    
    <div class="charts-grid">
        <div class="chart-container">
            <h3>Vulnerability Distribution</h3>
            <div id="vulnerability-chart"></div>
        </div>
        <div class="chart-container">
            <h3>Compliance Status</h3>
            <div id="compliance-chart"></div>
        </div>
        <div class="chart-container">
            <h3>Timeline</h3>
            <div id="timeline-chart"></div>
        </div>
        <div class="chart-container">
            <h3>Real-time Logs</h3>
            <div id="logs" class="log-container"></div>
        </div>
    </div>
    
    <script>
        let ws = null;
        
        function connectWebSocket() {
            ws = new WebSocket('ws://localhost:8080/ws');
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                updateDashboard(data);
            };
            ws.onclose = function() {
                setTimeout(connectWebSocket, 1000);
            };
        }
        
        function updateDashboard(data) {
            if (data.type === 'stats') {
                document.getElementById('total-scans').textContent = data.total_scans;
                document.getElementById('vulnerabilities').textContent = data.vulnerabilities_found;
                document.getElementById('compliance-violations').textContent = data.compliance_violations;
                document.getElementById('zero-day').textContent = data.zero_day_detections;
                document.getElementById('post-exploitation').textContent = data.post_exploitation_success;
            } else if (data.type === 'log') {
                const logs = document.getElementById('logs');
                const logEntry = document.createElement('div');
                logEntry.className = 'log-entry';
                logEntry.innerHTML = `<span class="${data.level}">[${data.timestamp}] ${data.message}</span>`;
                logs.appendChild(logEntry);
                logs.scrollTop = logs.scrollHeight;
            }
        }
        
        async function startScan() {
            const target = prompt('Enter target URL:');
            if (target) {
                await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target, scan_type: 'comprehensive'})
                });
            }
        }
        
        async function checkCompliance() {
            const target = prompt('Enter target URL:');
            if (target) {
                await fetch('/api/compliance-check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target, frameworks: ['OWASP', 'PCI', 'GDPR', 'SOX']})
                });
            }
        }
        
        async function postExploitation() {
            const target = prompt('Enter target URL:');
            if (target) {
                await fetch('/api/post-exploitation', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target, techniques: ['privilege_escalation', 'lateral_movement', 'persistence', 'data_exfiltration']})
                });
            }
        }
        
        async function zeroDayDetection() {
            const target = prompt('Enter target URL:');
            if (target) {
                await fetch('/api/zero-day', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                });
            }
        }
        
        async function generatePayload() {
            const vulnType = prompt('Enter vulnerability type:');
            if (vulnType) {
                await fetch('/api/payload-generator', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({vulnerability_type: vulnType})
                });
            }
        }
        
        async function startFuzzing() {
            const target = prompt('Enter target URL:');
            if (target) {
                await fetch('/api/fuzzing', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                });
            }
        }
        
        async function cryptoAnalysis() {
            const target = prompt('Enter target URL:');
            if (target) {
                await fetch('/api/crypto-analysis', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                });
            }
        }
        
        async function networkAnalysis() {
            const target = prompt('Enter target URL:');
            if (target) {
                await fetch('/api/network-analysis', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: target})
                });
            }
        }
        
        // Initialize dashboard
        connectWebSocket();
        loadCharts();
        
        async function loadCharts() {
            // Load vulnerability chart
            const vulnData = await fetch('/api/charts/vulnerabilities').then(r => r.json());
            Plotly.newPlot('vulnerability-chart', vulnData.data, vulnData.layout);
            
            // Load compliance chart
            const complianceData = await fetch('/api/charts/compliance').then(r => r.json());
            Plotly.newPlot('compliance-chart', complianceData.data, complianceData.layout);
            
            // Load timeline chart
            const timelineData = await fetch('/api/charts/timeline').then(r => r.json());
            Plotly.newPlot('timeline-chart', timelineData.data, timelineData.layout);
        }
        
        // Auto-refresh every 5 seconds
        setInterval(loadCharts, 5000);
    </script>
</body>
</html>
        """
    
    async def _get_dashboard_stats(self) -> DashboardStats:
        """Get dashboard statistics"""
        total_scans = self.db_session.query(ScanResult).count()
        vulnerabilities_found = self.db_session.query(ScanResult).filter(ScanResult.vulnerability_type.isnot(None)).count()
        compliance_violations = self.db_session.query(ComplianceResult).filter(ComplianceResult.status == "FAIL").count()
        zero_day_detections = self.db_session.query(ZeroDayResult).count()
        post_exploitation_success = self.db_session.query(PostExploitationResult).filter(PostExploitationResult.success == True).count()
        
        return DashboardStats(
            total_scans=total_scans,
            vulnerabilities_found=vulnerabilities_found,
            compliance_violations=compliance_violations,
            zero_day_detections=zero_day_detections,
            post_exploitation_success=post_exploitation_success
        )
    
    async def _get_scan_results(self) -> List[Dict]:
        """Get scan results"""
        results = self.db_session.query(ScanResult).order_by(ScanResult.timestamp.desc()).limit(100).all()
        return [
            {
                "id": result.id,
                "target": result.target,
                "scan_type": result.scan_type,
                "vulnerability_type": result.vulnerability_type,
                "severity": result.severity,
                "description": result.description,
                "timestamp": result.timestamp.isoformat(),
                "compliance_violation": result.compliance_violation,
                "owasp_category": result.owasp_category
            }
            for result in results
        ]
    
    async def _get_compliance_results(self) -> List[Dict]:
        """Get compliance results"""
        results = self.db_session.query(ComplianceResult).order_by(ComplianceResult.timestamp.desc()).limit(100).all()
        return [
            {
                "id": result.id,
                "target": result.target,
                "framework": result.framework,
                "check_name": result.check_name,
                "status": result.status,
                "description": result.description,
                "recommendation": result.recommendation,
                "severity": result.severity,
                "timestamp": result.timestamp.isoformat()
            }
            for result in results
        ]
    
    async def _get_post_exploitation_results(self) -> List[Dict]:
        """Get post-exploitation results"""
        results = self.db_session.query(PostExploitationResult).order_by(PostExploitationResult.timestamp.desc()).limit(100).all()
        return [
            {
                "id": result.id,
                "target": result.target,
                "technique": result.technique,
                "success": result.success,
                "details": result.details,
                "timestamp": result.timestamp.isoformat()
            }
            for result in results
        ]
    
    async def _get_zero_day_results(self) -> List[Dict]:
        """Get zero-day results"""
        results = self.db_session.query(ZeroDayResult).order_by(ZeroDayResult.timestamp.desc()).limit(100).all()
        return [
            {
                "id": result.id,
                "target": result.target,
                "vulnerability_type": result.vulnerability_type,
                "confidence": result.confidence,
                "details": result.details,
                "timestamp": result.timestamp.isoformat()
            }
            for result in results
        ]
    
    async def _start_scan(self, request: ScanRequest) -> Dict:
        """Start a security scan"""
        try:
            # Execute scan using engine
            scan_result = await self.engine.scan_target(request.target, request.scan_type, request.options)
            
            # Store in database
            db_result = ScanResult(
                target=request.target,
                scan_type=request.scan_type,
                vulnerability_type=scan_result.get('vulnerability_type'),
                severity=scan_result.get('severity'),
                description=scan_result.get('description'),
                payload=scan_result.get('payload'),
                response=scan_result.get('response'),
                compliance_violation=scan_result.get('compliance_violation', False),
                owasp_category=scan_result.get('owasp_category')
            )
            self.db_session.add(db_result)
            self.db_session.commit()
            
            # Notify connected clients
            await self._broadcast({
                "type": "scan_complete",
                "data": scan_result
            })
            
            return {"status": "success", "result": scan_result}
            
        except Exception as e:
            self.logger.error(f"[-] Scan failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    async def _compliance_check(self, request: ComplianceRequest) -> Dict:
        """Perform compliance checking"""
        try:
            results = []
            
            for framework in request.frameworks:
                framework_results = await self.compliance_checker.check_compliance(
                    request.target, framework
                )
                results.extend(framework_results)
                
                # Store in database
                for result in framework_results:
                    db_result = ComplianceResult(
                        target=request.target,
                        framework=framework,
                        check_name=result['check_name'],
                        status=result['status'],
                        description=result['description'],
                        recommendation=result['recommendation'],
                        severity=result['severity']
                    )
                    self.db_session.add(db_result)
            
            self.db_session.commit()
            
            # Notify connected clients
            await self._broadcast({
                "type": "compliance_check_complete",
                "data": results
            })
            
            return {"status": "success", "results": results}
            
        except Exception as e:
            self.logger.error(f"[-] Compliance check failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    async def _post_exploitation(self, request: PostExploitationRequest) -> Dict:
        """Perform post-exploitation techniques"""
        try:
            results = []
            
            for technique in request.techniques:
                technique_result = await self.post_exploitation.execute_technique(
                    request.target, technique
                )
                results.append(technique_result)
                
                # Store in database
                db_result = PostExploitationResult(
                    target=request.target,
                    technique=technique,
                    success=technique_result['success'],
                    details=technique_result['details']
                )
                self.db_session.add(db_result)
            
            self.db_session.commit()
            
            # Notify connected clients
            await self._broadcast({
                "type": "post_exploitation_complete",
                "data": results
            })
            
            return {"status": "success", "results": results}
            
        except Exception as e:
            self.logger.error(f"[-] Post-exploitation failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    async def _get_vulnerability_chart(self) -> Dict:
        """Generate vulnerability distribution chart"""
        try:
            # Get vulnerability data
            vuln_data = self.db_session.query(ScanResult.vulnerability_type, 
                                            func.count(ScanResult.id)).group_by(ScanResult.vulnerability_type).all()
            
            labels = [item[0] or 'Unknown' for item in vuln_data]
            values = [item[1] for item in vuln_data]
            
            data = [go.Pie(labels=labels, values=values, hole=0.3)]
            layout = go.Layout(
                title="Vulnerability Distribution",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#00ff00')
            )
            
            return {"data": data, "layout": layout}
            
        except Exception as e:
            self.logger.error(f"[-] Chart generation failed: {e}")
            return {"data": [], "layout": {}}
    
    async def _get_compliance_chart(self) -> Dict:
        """Generate compliance status chart"""
        try:
            # Get compliance data
            compliance_data = self.db_session.query(ComplianceResult.framework, 
                                                  ComplianceResult.status,
                                                  func.count(ComplianceResult.id)).group_by(
                                                  ComplianceResult.framework, 
                                                  ComplianceResult.status).all()
            
            frameworks = list(set([item[0] for item in compliance_data]))
            statuses = ['PASS', 'FAIL', 'WARNING']
            
            data = []
            for status in statuses:
                values = []
                for framework in frameworks:
                    count = next((item[2] for item in compliance_data 
                                if item[0] == framework and item[1] == status), 0)
                    values.append(count)
                
                data.append(go.Bar(name=status, x=frameworks, y=values))
            
            layout = go.Layout(
                title="Compliance Status by Framework",
                barmode='stack',
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#00ff00')
            )
            
            return {"data": data, "layout": layout}
            
        except Exception as e:
            self.logger.error(f"[-] Chart generation failed: {e}")
            return {"data": [], "layout": {}}
    
    async def _get_timeline_chart(self) -> Dict:
        """Generate timeline chart"""
        try:
            # Get timeline data
            timeline_data = self.db_session.query(
                func.date(ScanResult.timestamp).label('date'),
                func.count(ScanResult.id).label('count')
            ).group_by(func.date(ScanResult.timestamp)).all()
            
            dates = [item[0] for item in timeline_data]
            counts = [item[1] for item in timeline_data]
            
            data = [go.Scatter(x=dates, y=counts, mode='lines+markers', line=dict(color='#00ff00'))]
            layout = go.Layout(
                title="Scan Activity Timeline",
                xaxis=dict(title="Date"),
                yaxis=dict(title="Number of Scans"),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#00ff00')
            )
            
            return {"data": data, "layout": layout}
            
        except Exception as e:
            self.logger.error(f"[-] Chart generation failed: {e}")
            return {"data": [], "layout": {}}
    
    async def _handle_websocket(self, websocket: WebSocket):
        """Handle WebSocket connections"""
        await websocket.accept()
        self.connected_clients.append(websocket)
        
        try:
            while True:
                data = await websocket.receive_text()
                # Handle incoming messages if needed
        except WebSocketDisconnect:
            self.connected_clients.remove(websocket)
    
    async def _broadcast(self, message: Dict):
        """Broadcast message to all connected clients"""
        if self.connected_clients:
            message_json = json.dumps(message)
            for client in self.connected_clients:
                try:
                    await client.send_text(message_json)
                except:
                    self.connected_clients.remove(client)
    
    def run(self, host: str = "localhost", port: int = 8080):
        """Run the dashboard"""
        self.logger.info(f"[*] Starting AresProbe Dashboard on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port)
