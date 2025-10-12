# AresProbe API Reference

## Table of Contents
- [Core Engine](#core-engine)
- [SQL Injection Engine](#sql-injection-engine)
- [Vulnerability Scanner](#vulnerability-scanner)
- [AI Engine](#ai-engine)
- [Performance Optimizer](#performance-optimizer)
- [Configuration](#configuration)
- [Error Handling](#error-handling)

## Core Engine

### AresEngine

The main orchestration engine for all security testing operations.

#### Methods

##### `initialize() -> bool`
Initialize the AresProbe engine and all its components.

**Returns:**
- `bool`: True if initialization successful, False otherwise

**Example:**
```python
from aresprobe.core.engine import AresEngine

engine = AresEngine()
if engine.initialize():
    print("Engine initialized successfully")
```

##### `run_scan(config: ScanConfig) -> Dict[str, Any]`
Execute a comprehensive security scan based on the provided configuration.

**Parameters:**
- `config` (ScanConfig): Scan configuration object

**Returns:**
- `Dict[str, Any]`: Scan results containing vulnerabilities and statistics

**Example:**
```python
from aresprobe.core.engine import ScanConfig, ScanType

config = ScanConfig(
    target_url="http://example.com?id=1",
    scan_types=[ScanType.SQL_INJECTION, ScanType.XSS],
    threads=20,
    timeout=30
)

results = engine.run_scan(config)
print(f"Found {len(results['results'])} vulnerability types")
```

##### `start_proxy(port: int = 8080) -> bool`
Start the HTTP/HTTPS proxy server for traffic interception.

**Parameters:**
- `port` (int): Port number for the proxy server (default: 8080)

**Returns:**
- `bool`: True if proxy started successfully, False otherwise

##### `stop_proxy()`
Stop the currently running proxy server.

##### `generate_report(output_file: str = None) -> str`
Generate a detailed security report from the last scan results.

**Parameters:**
- `output_file` (str, optional): File path to save the report

**Returns:**
- `str`: Formatted report content

### ScanConfig

Configuration class for security scans.

#### Constructor Parameters

```python
ScanConfig(
    target_url: str,                    # Target URL to scan
    scan_types: List[ScanType],         # Types of scans to perform
    proxy_enabled: bool = True,         # Enable proxy interception
    proxy_port: int = 8080,            # Proxy server port
    threads: int = 10,                  # Number of concurrent threads
    timeout: int = 30,                  # Request timeout in seconds
    user_agent: str = "AresProbe/1.0", # User agent string
    cookies: Optional[Dict[str, str]] = None,  # Custom cookies
    headers: Optional[Dict[str, str]] = None,  # Custom headers
    auth: Optional[tuple] = None,       # Authentication credentials
    follow_redirects: bool = True,      # Follow HTTP redirects
    verify_ssl: bool = False           # Verify SSL certificates
)
```

## SQL Injection Engine

### SuperSQLInjector

Advanced SQL injection testing engine with multiple techniques and payloads.

#### Methods

##### `scan_target_superior(target_url: str, config) -> Dict[str, Any]`
Perform superior SQL injection scanning with AI-powered detection and WAF bypass.

**Parameters:**
- `target_url` (str): Target URL to scan
- `config`: Scan configuration object

**Returns:**
- `Dict[str, Any]`: Comprehensive scan results

**Example:**
```python
from aresprobe.core.sql_injector import SuperSQLInjector

injector = SuperSQLInjector()
results = injector.scan_target_superior("http://example.com?id=1", config)

if results['vulnerabilities']:
    print("SQL injection vulnerabilities found!")
    for vuln in results['vulnerabilities']:
        print(f"Parameter: {vuln['parameter']}")
        print(f"Payload: {vuln['payload']}")
        print(f"Type: {vuln['injection_type']}")
```

##### `extract_data(target_url: str, param_name: str, param_value: str, injection_type: str, config) -> Dict[str, Any]`
Extract data from the target using the specified injection type.

**Parameters:**
- `target_url` (str): Target URL
- `param_name` (str): Parameter name
- `param_value` (str): Parameter value
- `injection_type` (str): Type of injection to use
- `config`: Configuration object

**Returns:**
- `Dict[str, Any]`: Extracted data and metadata

#### Injection Types

- `SQLInjectionType.BOOLEAN_BLIND`: Boolean-based blind injection
- `SQLInjectionType.TIME_BASED`: Time-based blind injection
- `SQLInjectionType.UNION_BASED`: UNION-based injection
- `SQLInjectionType.ERROR_BASED`: Error-based injection
- `SQLInjectionType.STACKED_QUERIES`: Stacked queries injection
- `SQLInjectionType.POLYMORPHIC`: Polymorphic injection
- `SQLInjectionType.AI_POWERED`: AI-powered injection
- `SQLInjectionType.CONTEXT_AWARE`: Context-aware injection

## Vulnerability Scanner

### VulnerabilityScanner

Advanced web vulnerability scanner with multiple attack vectors.

#### Methods

##### `scan_xss(target_url: str, config) -> Dict[str, Any]`
Scan for Cross-Site Scripting (XSS) vulnerabilities.

**Parameters:**
- `target_url` (str): Target URL to scan
- `config`: Scan configuration

**Returns:**
- `Dict[str, Any]`: XSS scan results

##### `scan_directory_traversal(target_url: str, config) -> Dict[str, Any]`
Scan for directory traversal vulnerabilities.

##### `scan_command_injection(target_url: str, config) -> Dict[str, Any]`
Scan for command injection vulnerabilities.

##### `scan_xxe(target_url: str, config) -> Dict[str, Any]`
Scan for XML External Entity (XXE) vulnerabilities.

##### `scan_ssrf(target_url: str, config) -> Dict[str, Any]`
Scan for Server-Side Request Forgery (SSRF) vulnerabilities.

## AI Engine

### AIEngine

Advanced AI-powered vulnerability analysis and payload generation.

#### Methods

##### `analyze_response(response_text: str, response_headers: Dict[str, str], url: str, method: str = "GET") -> List[Any]`
Analyze HTTP response for potential vulnerabilities using AI.

**Parameters:**
- `response_text` (str): Response body content
- `response_headers` (Dict[str, str]): Response headers
- `url` (str): Request URL
- `method` (str): HTTP method used

**Returns:**
- `List[Any]`: List of detected vulnerabilities and analysis results

##### `generate_smart_payloads(vulnerability_type: str, context: Dict[str, Any], count: int = 5) -> List[str]`
Generate intelligent payloads based on vulnerability type and context.

**Parameters:**
- `vulnerability_type` (str): Type of vulnerability
- `context` (Dict[str, Any]): Context information
- `count` (int): Number of payloads to generate

**Returns:**
- `List[str]`: Generated payloads

## Performance Optimizer

### PerformanceOptimizer

Advanced performance optimization and memory management system.

#### Methods

##### `start_monitoring()`
Start performance monitoring in background thread.

##### `stop_monitoring()`
Stop performance monitoring.

##### `collect_metrics() -> PerformanceMetrics`
Collect current performance metrics.

**Returns:**
- `PerformanceMetrics`: Current performance statistics

##### `get_performance_report() -> Dict[str, Any]`
Get comprehensive performance report.

**Returns:**
- `Dict[str, Any]`: Detailed performance analysis

#### Performance Metrics

```python
@dataclass
class PerformanceMetrics:
    cpu_usage: float              # CPU usage percentage
    memory_usage: float           # Memory usage in MB
    memory_available: float       # Available memory in MB
    thread_count: int             # Number of active threads
    active_connections: int       # Number of active connections
    response_time_avg: float      # Average response time
    requests_per_second: float    # Requests per second
    cache_hit_ratio: float        # Cache hit ratio
    gc_collections: int           # Garbage collection count
    timestamp: float              # Timestamp
```

## Configuration

### OptimizationConfig

Performance optimization configuration.

```python
@dataclass
class OptimizationConfig:
    max_memory_usage: float = 0.8        # Maximum memory usage (80%)
    max_threads: int = 50                # Maximum thread count
    max_connections: int = 100           # Maximum connections
    gc_threshold: int = 1000             # GC trigger threshold
    cache_size_limit: int = 10000        # Cache size limit
    response_time_threshold: float = 5.0 # Response time threshold
    optimization_level: OptimizationLevel = OptimizationLevel.BASIC
    enable_profiling: bool = False       # Enable profiling
    enable_memory_tracking: bool = True  # Enable memory tracking
```

### AggressiveConfig

Aggressive testing configuration for penetration testing.

```python
{
    "attack_mode": "aggressive",
    "injection_techniques": [
        "union_based",
        "error_based", 
        "boolean_blind",
        "time_based",
        "stacked_queries",
        "waf_bypass",
        "encoding_bypass"
    ],
    "max_payloads_per_technique": 100,
    "payload_encoding": [
        "url", "double_url", "html", "unicode", 
        "hex", "base64", "utf8", "utf16", "ascii", "binary"
    ],
    "bypass_techniques": [
        "comment_bypass", "case_variation", "whitespace_bypass",
        "function_bypass", "operator_bypass", "keyword_bypass",
        "encoding_bypass", "time_delay_bypass", "chunked_bypass"
    ],
    "request_delay": 0.1,
    "max_concurrent_requests": 50,
    "timeout": 30,
    "retry_attempts": 3
}
```

## Error Handling

### Exception Types

#### `AresProbeError`
Base exception class for all AresProbe errors.

#### `InitializationError`
Raised when engine initialization fails.

#### `ScanError`
Raised when scan execution fails.

#### `ProxyError`
Raised when proxy operations fail.

#### `ConfigurationError`
Raised when configuration is invalid.

### Error Handling Example

```python
from aresprobe.core.engine import AresEngine, ScanConfig, ScanType
from aresprobe.exceptions import AresProbeError, ScanError

try:
    engine = AresEngine()
    if not engine.initialize():
        raise InitializationError("Failed to initialize engine")
    
    config = ScanConfig(
        target_url="http://example.com",
        scan_types=[ScanType.SQL_INJECTION]
    )
    
    results = engine.run_scan(config)
    
except ScanError as e:
    print(f"Scan failed: {e}")
except AresProbeError as e:
    print(f"AresProbe error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
finally:
    engine.cleanup()
```

## Usage Examples

### Basic SQL Injection Scan

```python
from aresprobe.core.engine import AresEngine, ScanConfig, ScanType

# Initialize engine
engine = AresEngine()
engine.initialize()

# Configure scan
config = ScanConfig(
    target_url="http://vulnerable-site.com/page.php?id=1",
    scan_types=[ScanType.SQL_INJECTION],
    threads=20,
    timeout=30
)

# Run scan
results = engine.run_scan(config)

# Process results
if results['results']['sql_injection']['vulnerabilities']:
    print("SQL injection vulnerabilities found!")
    for vuln in results['results']['sql_injection']['vulnerabilities']:
        print(f"Parameter: {vuln['parameter']}")
        print(f"Payload: {vuln['payload']}")
        print(f"Severity: {vuln['severity']}")

# Generate report
report = engine.generate_report("scan_report.html")
print(f"Report saved to: scan_report.html")

# Cleanup
engine.cleanup()
```

### Advanced Multi-Vector Scan

```python
from aresprobe.core.engine import AresEngine, ScanConfig, ScanType

engine = AresEngine()
engine.initialize()

# Comprehensive scan
config = ScanConfig(
    target_url="http://target.com",
    scan_types=[
        ScanType.SQL_INJECTION,
        ScanType.XSS,
        ScanType.DIRECTORY_TRAVERSAL,
        ScanType.COMMAND_INJECTION,
        ScanType.XXE,
        ScanType.SSRF
    ],
    proxy_enabled=True,
    threads=50,
    timeout=60
)

results = engine.run_scan(config)

# Analyze results
total_vulnerabilities = sum(
    len(scan_results.get('vulnerabilities', []))
    for scan_results in results['results'].values()
)

print(f"Total vulnerabilities found: {total_vulnerabilities}")

engine.cleanup()
```

### Performance Monitoring

```python
from aresprobe.core.performance_optimizer import PerformanceOptimizer, OptimizationConfig

# Configure optimization
config = OptimizationConfig(
    max_memory_usage=0.8,
    max_threads=100,
    optimization_level=OptimizationLevel.AGGRESSIVE,
    enable_profiling=True
)

# Initialize optimizer
optimizer = PerformanceOptimizer(config)
optimizer.start_monitoring()

# Your scanning code here...

# Get performance report
report = optimizer.get_performance_report()
print(f"CPU Usage: {report['current_metrics']['cpu_usage']}%")
print(f"Memory Usage: {report['current_metrics']['memory_usage_mb']} MB")
print(f"Response Time: {report['current_metrics']['response_time_avg']}s")

optimizer.cleanup()
```
