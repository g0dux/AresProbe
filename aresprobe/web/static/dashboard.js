/**
 * AresProbe Web Dashboard JavaScript
 * Real-time dashboard functionality
 */

class AresProbeDashboard {
    constructor() {
        this.apiBaseUrl = '/api/v1';
        this.wsUrl = 'ws://localhost:8080';
        this.authToken = localStorage.getItem('aresprobe_token');
        this.refreshInterval = 30000; // 30 seconds
        this.charts = {};
        this.websockets = {};
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadDashboardData();
        this.startAutoRefresh();
        this.connectWebSockets();
    }
    
    setupEventListeners() {
        // Refresh button
        document.getElementById('refresh-btn')?.addEventListener('click', () => {
            this.refreshData();
        });
        
        // New scan button
        document.getElementById('new-scan-btn')?.addEventListener('click', () => {
            this.showNewScanModal();
        });
        
        // Modal form submission
        document.getElementById('new-scan-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.submitNewScan();
        });
    }
    
    async loadDashboardData() {
        try {
            this.showLoading(true);
            
            const [stats, scans, performance] = await Promise.all([
                this.apiRequest('/dashboard'),
                this.apiRequest('/scans'),
                this.apiRequest('/performance')
            ]);
            
            this.updateDashboardStats(stats.stats);
            this.updateCharts(stats.stats);
            this.updatePerformanceMetrics(performance.current_metrics);
            this.updateRecentScans(stats.stats.recent_scans);
            this.updateActiveScans(scans.filter(scan => scan.status === 'running'));
            
            this.showLoading(false);
            
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
            this.showError('Failed to load dashboard data');
        }
    }
    
    updateDashboardStats(stats) {
        document.getElementById('total-scans').textContent = stats.total_scans || 0;
        document.getElementById('active-scans').textContent = stats.active_scans || 0;
        document.getElementById('vulnerabilities-found').textContent = stats.vulnerabilities_found || 0;
        
        const systemHealth = this.calculateSystemHealth(stats.performance_metrics);
        document.getElementById('system-health').textContent = systemHealth + '%';
        
        // Update health indicator
        const healthElement = document.getElementById('system-health');
        if (systemHealth >= 80) {
            healthElement.className = 'metric-value text-success';
        } else if (systemHealth >= 60) {
            healthElement.className = 'metric-value text-warning';
        } else {
            healthElement.className = 'metric-value text-danger';
        }
    }
    
    calculateSystemHealth(metrics) {
        let health = 100;
        
        if (metrics.cpu_usage > 80) health -= 20;
        else if (metrics.cpu_usage > 60) health -= 10;
        
        if (metrics.memory_usage > 85) health -= 25;
        else if (metrics.memory_usage > 70) health -= 15;
        
        if (metrics.error_rate > 0.1) health -= 30;
        else if (metrics.error_rate > 0.05) health -= 15;
        
        return Math.max(0, health);
    }
    
    updateCharts(stats) {
        this.updateVulnerabilityChart(stats.severity_distribution);
        this.updateScanActivityChart();
    }
    
    updateVulnerabilityChart(severityData) {
        const ctx = document.getElementById('vulnerabilityChart');
        if (!ctx || !this.charts.vulnerability) return;
        
        const data = [
            severityData.critical || 0,
            severityData.high || 0,
            severityData.medium || 0,
            severityData.low || 0,
            severityData.info || 0
        ];
        
        this.charts.vulnerability.data.datasets[0].data = data;
        this.charts.vulnerability.update();
    }
    
    updateScanActivityChart() {
        const ctx = document.getElementById('scanActivityChart');
        if (!ctx || !this.charts.scanActivity) return;
        
        // Generate mock time series data
        const now = new Date();
        const labels = [];
        const scanData = [];
        const vulnData = [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
            labels.push(date.toLocaleDateString());
            scanData.push(Math.floor(Math.random() * 20) + 5);
            vulnData.push(Math.floor(Math.random() * 50) + 10);
        }
        
        this.charts.scanActivity.data.labels = labels;
        this.charts.scanActivity.data.datasets[0].data = scanData;
        this.charts.scanActivity.data.datasets[1].data = vulnData;
        this.charts.scanActivity.update();
    }
    
    updatePerformanceMetrics(metrics) {
        // CPU Usage
        const cpuProgress = document.getElementById('cpu-progress');
        const cpuText = document.getElementById('cpu-text');
        if (cpuProgress && cpuText) {
            cpuProgress.style.width = metrics.cpu_usage + '%';
            cpuText.textContent = metrics.cpu_usage.toFixed(1) + '%';
        }
        
        // Memory Usage
        const memoryProgress = document.getElementById('memory-progress');
        const memoryText = document.getElementById('memory-text');
        if (memoryProgress && memoryText) {
            memoryProgress.style.width = metrics.memory_usage + '%';
            memoryText.textContent = metrics.memory_usage.toFixed(1) + '%';
        }
        
        // Network Throughput
        const networkElement = document.getElementById('network-throughput');
        if (networkElement) {
            networkElement.textContent = metrics.network_throughput.toFixed(1) + ' MB/s';
        }
        
        // Response Time
        const responseElement = document.getElementById('response-time');
        if (responseElement) {
            responseElement.textContent = (metrics.response_time * 1000).toFixed(0) + 'ms';
        }
    }
    
    updateRecentScans(scans) {
        const container = document.getElementById('recent-scans');
        if (!container) return;
        
        if (scans.length === 0) {
            container.innerHTML = '<div class="text-center text-muted">No recent scans</div>';
            return;
        }
        
        const html = scans.map(scan => `
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 border-bottom border-secondary">
                <div>
                    <div class="fw-bold">${scan.target}</div>
                    <small class="text-muted">${new Date(scan.started_at).toLocaleString()}</small>
                </div>
                <div>
                    <span class="badge bg-${this.getSeverityBadge(scan.status)}">${scan.status}</span>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = html;
    }
    
    updateActiveScans(scans) {
        const container = document.getElementById('active-scans-list');
        if (!container) return;
        
        if (scans.length === 0) {
            container.innerHTML = '<div class="text-center text-muted">No active scans</div>';
            return;
        }
        
        const html = scans.map(scan => `
            <div class="mb-3 p-3 border border-secondary rounded">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <div>
                        <div class="fw-bold">${scan.target}</div>
                        <small class="text-muted">Started: ${new Date(scan.started_at).toLocaleString()}</small>
                    </div>
                    <div>
                        <span class="badge bg-primary">${scan.progress.toFixed(0)}%</span>
                        <button class="btn btn-sm btn-outline-danger ms-2" onclick="dashboard.cancelScan('${scan.scan_id}')">
                            <i class="fas fa-stop"></i>
                        </button>
                    </div>
                </div>
                <div class="scan-progress">
                    <div class="scan-progress-bar" style="width: ${scan.progress}%"></div>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = html;
    }
    
    initializeCharts() {
        // Vulnerability Chart
        const vulnCtx = document.getElementById('vulnerabilityChart');
        if (vulnCtx) {
            this.charts.vulnerability = new Chart(vulnCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: [
                            '#da3633',
                            '#bf8700',
                            '#1f6feb',
                            '#238636',
                            '#8b949e'
                        ],
                        borderWidth: 2,
                        borderColor: '#30363d'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#c9d1d9',
                                padding: 20
                            }
                        }
                    }
                }
            });
        }
        
        // Scan Activity Chart
        const scanCtx = document.getElementById('scanActivityChart');
        if (scanCtx) {
            this.charts.scanActivity = new Chart(scanCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Scans Completed',
                        data: [],
                        borderColor: '#00FF41',
                        backgroundColor: 'rgba(0, 255, 65, 0.1)',
                        tension: 0.4
                    }, {
                        label: 'Vulnerabilities Found',
                        data: [],
                        borderColor: '#da3633',
                        backgroundColor: 'rgba(218, 54, 51, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#c9d1d9'
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: '#8b949e'
                            },
                            grid: {
                                color: '#30363d'
                            }
                        },
                        y: {
                            ticks: {
                                color: '#8b949e'
                            },
                            grid: {
                                color: '#30363d'
                            }
                        }
                    }
                }
            });
        }
    }
    
    connectWebSockets() {
        // Dashboard WebSocket
        try {
            this.websockets.dashboard = new WebSocket(`${this.wsUrl}/ws/dashboard`);
            this.websockets.dashboard.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleDashboardUpdate(data);
            };
        } catch (error) {
            console.warn('Failed to connect dashboard WebSocket:', error);
        }
        
        // Scans WebSocket
        try {
            this.websockets.scans = new WebSocket(`${this.wsUrl}/ws/scans`);
            this.websockets.scans.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleScanUpdate(data);
            };
        } catch (error) {
            console.warn('Failed to connect scans WebSocket:', error);
        }
    }
    
    handleDashboardUpdate(data) {
        if (data.type === 'dashboard_update') {
            // Update metrics in real-time
            const metrics = data.metrics;
            
            document.getElementById('active-scans').textContent = metrics.active_scans || 0;
            document.getElementById('vulnerabilities-found').textContent = metrics.vulnerabilities_found || 0;
            
            // Update performance metrics
            const cpuProgress = document.getElementById('cpu-progress');
            const cpuText = document.getElementById('cpu-text');
            if (cpuProgress && cpuText) {
                cpuProgress.style.width = metrics.cpu_usage + '%';
                cpuText.textContent = metrics.cpu_usage.toFixed(1) + '%';
            }
            
            const memoryProgress = document.getElementById('memory-progress');
            const memoryText = document.getElementById('memory-text');
            if (memoryProgress && memoryText) {
                memoryProgress.style.width = metrics.memory_usage + '%';
                memoryText.textContent = metrics.memory_usage.toFixed(1) + '%';
            }
        }
    }
    
    handleScanUpdate(data) {
        if (data.type === 'scan_update') {
            // Update scan progress in real-time
            data.scans.forEach(scan => {
                const scanElement = document.querySelector(`[data-scan-id="${scan.scan_id}"]`);
                if (scanElement) {
                    const progressBar = scanElement.querySelector('.scan-progress-bar');
                    const progressText = scanElement.querySelector('.badge');
                    
                    if (progressBar) {
                        progressBar.style.width = scan.progress + '%';
                    }
                    if (progressText) {
                        progressText.textContent = scan.progress.toFixed(0) + '%';
                    }
                }
            });
        }
    }
    
    showNewScanModal() {
        const modal = new bootstrap.Modal(document.getElementById('newScanModal'));
        modal.show();
    }
    
    async submitNewScan() {
        const targetUrl = document.getElementById('targetUrl').value;
        const scanTypes = Array.from(document.getElementById('scanTypes').selectedOptions).map(option => option.value);
        const optionsText = document.getElementById('scanOptions').value;
        
        if (!targetUrl) {
            this.showError('Please enter a target URL');
            return;
        }
        
        let options = {};
        if (optionsText.trim()) {
            try {
                options = JSON.parse(optionsText);
            } catch (e) {
                this.showError('Invalid JSON in options field');
                return;
            }
        }
        
        try {
            const response = await this.apiRequest('/scans', {
                method: 'POST',
                body: JSON.stringify({
                    target: targetUrl,
                    scan_types: scanTypes,
                    options: options
                })
            });
            
            this.showSuccess(`Scan started successfully! Scan ID: ${response.scan_id}`);
            
            // Close modal and refresh data
            bootstrap.Modal.getInstance(document.getElementById('newScanModal')).hide();
            document.getElementById('newScanForm').reset();
            
            // Refresh dashboard after a short delay
            setTimeout(() => {
                this.refreshData();
            }, 2000);
            
        } catch (error) {
            console.error('Failed to start scan:', error);
            this.showError('Failed to start scan: ' + error.message);
        }
    }
    
    async cancelScan(scanId) {
        try {
            await this.apiRequest(`/scans/${scanId}`, {
                method: 'DELETE'
            });
            
            this.showSuccess('Scan cancelled successfully');
            this.updateActiveScans([]); // Refresh active scans
        } catch (error) {
            console.error('Failed to cancel scan:', error);
            this.showError('Failed to cancel scan: ' + error.message);
        }
    }
    
    async apiRequest(endpoint, options = {}) {
        const url = this.apiBaseUrl + endpoint;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...(this.authToken && { 'Authorization': `Bearer ${this.authToken}` })
            },
            ...options
        };
        
        const response = await fetch(url, config);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'API request failed');
        }
        
        return data;
    }
    
    startAutoRefresh() {
        setInterval(() => {
            this.loadDashboardData();
        }, this.refreshInterval);
    }
    
    refreshData() {
        this.showToast('Refreshing dashboard data...', 'info');
        this.loadDashboardData();
    }
    
    showLoading(show) {
        const loadingElements = document.querySelectorAll('.loading');
        loadingElements.forEach(el => {
            el.style.display = show ? 'inline-block' : 'none';
        });
    }
    
    showError(message) {
        this.showToast(message, 'error');
    }
    
    showSuccess(message) {
        this.showToast(message, 'success');
    }
    
    showToast(message, type = 'info') {
        const toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) return;
        
        const toastId = 'toast-' + Date.now();
        
        const toastHtml = `
            <div class="toast" id="${toastId}" role="alert">
                <div class="toast-header">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'} text-${type} me-2"></i>
                    <strong class="me-auto">AresProbe</strong>
                    <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                </div>
                <div class="toast-body">
                    ${message}
                </div>
            </div>
        `;
        
        toastContainer.insertAdjacentHTML('beforeend', toastHtml);
        const toast = new bootstrap.Toast(document.getElementById(toastId));
        toast.show();
        
        // Remove toast element after it's hidden
        document.getElementById(toastId).addEventListener('hidden.bs.toast', function() {
            this.remove();
        });
    }
    
    getSeverityBadge(severity) {
        const badges = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success',
            'info': 'secondary',
            'completed': 'success',
            'running': 'primary',
            'failed': 'danger',
            'cancelled': 'secondary'
        };
        return badges[severity] || 'secondary';
    }
    
    cleanup() {
        // Close WebSocket connections
        Object.values(this.websockets).forEach(ws => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.close();
            }
        });
        
        // Destroy charts
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.dashboard = new AresProbeDashboard();
    window.dashboard.initializeCharts();
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (window.dashboard) {
        window.dashboard.cleanup();
    }
});
