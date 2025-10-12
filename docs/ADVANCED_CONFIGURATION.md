# AresProbe Advanced Configuration Guide

## Table of Contents
- [Overview](#overview)
- [Performance Optimization](#performance-optimization)
- [Security Configuration](#security-configuration)
- [Network Configuration](#network-configuration)
- [AI/ML Configuration](#aiml-configuration)
- [Plugin Configuration](#plugin-configuration)
- [Custom Payloads](#custom-payloads)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

## Overview

AresProbe offers extensive configuration options for advanced users who need fine-tuned control over scanning behavior, performance, and security features. This guide covers all advanced configuration options and their optimal settings for different scenarios.

## Performance Optimization

### Memory Management

```python
from aresprobe.core.performance_optimizer import OptimizationConfig, OptimizationLevel

# High-performance configuration
config = OptimizationConfig(
    max_memory_usage=0.9,              # Use up to 90% of available memory
    max_threads=200,                   # Maximum 200 concurrent threads
    max_connections=500,               # Maximum 500 concurrent connections
    gc_threshold=500,                  # Trigger GC every 500 operations
    cache_size_limit=50000,            # Cache up to 50,000 items
    response_time_threshold=2.0,       # Optimize if response time > 2s
    optimization_level=OptimizationLevel.MAXIMUM,
    enable_profiling=True,             # Enable detailed profiling
    enable_memory_tracking=True        # Track memory usage
)
```

### Thread Pool Configuration

```python
# Custom thread pool settings
thread_config = {
    'sql_injection': 50,      # 50 threads for SQL injection
    'xss_scanning': 30,       # 30 threads for XSS scanning
    'network_scan': 100,      # 100 threads for network scanning
    'ai_analysis': 20         # 20 threads for AI analysis
}

# Apply configuration
for pool_name, max_workers in thread_config.items():
    pool = optimizer.thread_manager.get_thread_pool(pool_name, max_workers)
```

### Connection Pooling

```python
# Advanced connection management
connection_config = {
    'max_connections_per_host': 50,
    'connection_timeout': 30,
    'keep_alive_timeout': 300,
    'max_retries': 5,
    'retry_delay': 1.0,
    'connection_pool_size': 1000
}
```

## Security Configuration

### Aggressive Testing Mode

```json
{
    "attack_mode": "maximum",
    "injection_techniques": [
        "union_based",
        "error_based",
        "boolean_blind",
        "time_based",
        "stacked_queries",
        "waf_bypass",
        "encoding_bypass",
        "polyglot_injection",
        "second_order_injection"
    ],
    "max_payloads_per_technique": 500,
    "payload_encoding": [
        "url", "double_url", "html", "unicode", "hex", "base64",
        "utf8", "utf16", "ascii", "binary", "rot13", "html_entities"
    ],
    "bypass_techniques": [
        "comment_bypass", "case_variation", "whitespace_bypass",
        "function_bypass", "operator_bypass", "keyword_bypass",
        "encoding_bypass", "time_delay_bypass", "chunked_bypass",
        "http_parameter_pollution", "nested_encoding"
    ],
    "request_delay": 0.05,
    "max_concurrent_requests": 100,
    "timeout": 60,
    "retry_attempts": 5,
    "allow_destructive": true,
    "test_drop_tables": false,
    "test_insert_data": true,
    "test_update_data": true
}
```

### WAF Bypass Configuration

```python
waf_bypass_config = {
    'techniques': [
        'comment_injection',
        'case_variation',
        'whitespace_manipulation',
        'function_replacement',
        'operator_substitution',
        'keyword_obfuscation',
        'encoding_manipulation',
        'time_delay_injection',
        'chunked_transfer_encoding',
        'http_parameter_pollution',
        'nested_encoding',
        'unicode_normalization'
    ],
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'curl/7.68.0',
        'wget/1.20.3'
    ],
    'headers': {
        'X-Forwarded-For': '127.0.0.1',
        'X-Real-IP': '127.0.0.1',
        'X-Originating-IP': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'X-Remote-Addr': '127.0.0.1'
    }
}
```

### Rate Limiting and Throttling

```python
rate_limiting_config = {
    'requests_per_second': 10,         # Maximum 10 requests per second
    'burst_size': 50,                  # Allow bursts of up to 50 requests
    'cooldown_period': 30,             # 30 second cooldown after burst
    'adaptive_throttling': True,       # Adjust based on response times
    'backoff_multiplier': 1.5,         # Exponential backoff multiplier
    'max_backoff': 60                  # Maximum backoff time in seconds
}
```

## Network Configuration

### Proxy Configuration

```python
proxy_config = {
    'enabled': True,
    'type': 'http',                    # http, https, socks4, socks5
    'host': '127.0.0.1',
    'port': 8080,
    'username': None,                  # Optional authentication
    'password': None,
    'rotation': True,                  # Rotate between multiple proxies
    'proxies': [
        {'host': '127.0.0.1', 'port': 8080},
        {'host': '127.0.0.1', 'port': 8081},
        {'host': '127.0.0.1', 'port': 8082}
    ]
}
```

### SSL/TLS Configuration

```python
ssl_config = {
    'verify_ssl': False,               # Skip SSL verification
    'ssl_version': 'TLSv1.2',         # TLS version
    'ciphers': 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
    'cert_file': None,                 # Client certificate file
    'key_file': None,                  # Client private key file
    'ca_file': None,                   # CA certificate file
    'check_hostname': False           # Skip hostname verification
}
```

### DNS Configuration

```python
dns_config = {
    'resolver': '8.8.8.8',            # DNS resolver
    'timeout': 5,                      # DNS timeout
    'retries': 3,                      # DNS retry attempts
    'cache_size': 1000,               # DNS cache size
    'cache_ttl': 300,                 # DNS cache TTL
    'use_ipv6': True,                 # Enable IPv6 resolution
    'custom_hosts': {                 # Custom host mappings
        'example.com': '192.168.1.100'
    }
}
```

## AI/ML Configuration

### AI Engine Configuration

```python
ai_config = {
    'model_path': './models/',
    'confidence_threshold': 0.7,
    'max_payloads': 100,
    'learning_rate': 0.001,
    'batch_size': 32,
    'epochs': 100,
    'validation_split': 0.2,
    'enable_online_learning': True,
    'model_update_interval': 3600,    # Update model every hour
    'feature_extraction': {
        'use_word_embeddings': True,
        'embedding_dimension': 128,
        'max_sequence_length': 512,
        'vocabulary_size': 10000
    }
}
```

### Machine Learning Models

```python
ml_models = {
    'vulnerability_detection': {
        'model_type': 'transformer',
        'architecture': 'BERT',
        'pretrained_model': 'bert-base-uncased',
        'fine_tuned': True,
        'confidence_threshold': 0.8
    },
    'payload_generation': {
        'model_type': 'generative',
        'architecture': 'GPT-2',
        'max_length': 256,
        'temperature': 0.8,
        'top_p': 0.9
    },
    'anomaly_detection': {
        'model_type': 'isolation_forest',
        'contamination': 0.1,
        'n_estimators': 100,
        'max_samples': 256
    }
}
```

## Plugin Configuration

### Plugin System Configuration

```python
plugin_config = {
    'enabled': True,
    'auto_load': True,
    'plugin_directory': './plugins/',
    'custom_plugins_directory': './custom_plugins/',
    'plugin_timeout': 30,
    'max_plugin_instances': 10,
    'sandbox_mode': True,             # Run plugins in sandbox
    'allowed_imports': [              # Whitelist of allowed imports
        'requests', 'urllib3', 'json', 'time', 'random'
    ],
    'blocked_imports': [              # Blacklist of blocked imports
        'os', 'subprocess', 'sys', 'importlib'
    ]
}
```

### Custom Plugin Example

```python
# custom_plugins/advanced_scanner.py
from aresprobe.plugins.base import BasePlugin

class AdvancedScannerPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "Advanced Scanner"
        self.version = "1.0.0"
        self.description = "Advanced vulnerability scanner"
    
    def scan(self, target_url: str, config: dict) -> dict:
        """Custom scanning logic"""
        results = {
            'vulnerabilities': [],
            'scan_time': 0,
            'total_tests': 0
        }
        
        # Custom scanning implementation
        # ...
        
        return results
    
    def get_plugin_info(self) -> dict:
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': 'Your Name',
            'license': 'MIT'
        }
```

## Custom Payloads

### SQL Injection Payloads

```python
custom_sql_payloads = {
    'mysql': {
        'information_gathering': [
            "' UNION SELECT version(),user(),database()--",
            "' UNION SELECT @@version,@@datadir,@@hostname--",
            "' UNION SELECT table_name,table_schema FROM information_schema.tables--"
        ],
        'data_extraction': [
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT email,phone FROM customers--",
            "' UNION SELECT CONCAT(username,':',password) FROM users--"
        ],
        'privilege_escalation': [
            "' UNION SELECT user,password FROM mysql.user WHERE user='root'--",
            "' UNION SELECT grantee,privilege_type FROM information_schema.user_privileges--"
        ]
    },
    'postgresql': {
        'information_gathering': [
            "' UNION SELECT version(),current_user,current_database()--",
            "' UNION SELECT tablename,schemaname FROM pg_tables--"
        ],
        'data_extraction': [
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT email,phone FROM customers--"
        ]
    }
}
```

### XSS Payloads

```python
custom_xss_payloads = {
    'basic': [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>"
    ],
    'advanced': [
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>"
    ],
    'bypass': [
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))>"
    ]
}
```

## Environment Variables

### Core Configuration

```bash
# AresProbe Core Settings
export ARESPROBE_LOG_LEVEL=INFO
export ARESPROBE_TIMEOUT=30
export ARESPROBE_THREADS=20
export ARESPROBE_MAX_MEMORY=0.8
export ARESPROBE_CACHE_SIZE=10000

# Performance Settings
export ARESPROBE_OPTIMIZATION_LEVEL=aggressive
export ARESPROBE_ENABLE_PROFILING=true
export ARESPROBE_MEMORY_TRACKING=true

# Security Settings
export ARESPROBE_ATTACK_MODE=aggressive
export ARESPROBE_ALLOW_DESTRUCTIVE=false
export ARESPROBE_WAF_BYPASS=true

# Network Settings
export ARESPROBE_PROXY_ENABLED=true
export ARESPROBE_PROXY_PORT=8080
export ARESPROBE_VERIFY_SSL=false
export ARESPROBE_FOLLOW_REDIRECTS=true

# AI/ML Settings
export ARESPROBE_AI_ENABLED=true
export ARESPROBE_ML_MODELS_PATH=./models/
export ARESPROBE_AI_CONFIDENCE=0.7

# Plugin Settings
export ARESPROBE_PLUGINS_ENABLED=true
export ARESPROBE_PLUGIN_DIRECTORY=./plugins/
export ARESPROBE_PLUGIN_TIMEOUT=30
```

### Docker Environment

```dockerfile
# Dockerfile
FROM python:3.9-slim

# Set environment variables
ENV ARESPROBE_LOG_LEVEL=INFO
ENV ARESPROBE_OPTIMIZATION_LEVEL=aggressive
ENV ARESPROBE_AI_ENABLED=true
ENV ARESPROBE_PLUGINS_ENABLED=true

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application
COPY . /app
WORKDIR /app

# Run AresProbe
CMD ["python", "main.py"]
```

## Troubleshooting

### Common Issues

#### Memory Issues

```python
# Symptoms: High memory usage, out of memory errors
# Solution: Adjust memory configuration

config = OptimizationConfig(
    max_memory_usage=0.6,              # Reduce to 60%
    gc_threshold=250,                  # More frequent GC
    cache_size_limit=5000,             # Smaller cache
    optimization_level=OptimizationLevel.BASIC
)
```

#### Performance Issues

```python
# Symptoms: Slow scanning, high CPU usage
# Solution: Optimize thread and connection settings

config = OptimizationConfig(
    max_threads=50,                    # Reduce thread count
    max_connections=100,               # Reduce connections
    response_time_threshold=3.0,       # Increase threshold
    optimization_level=OptimizationLevel.AGGRESSIVE
)
```

#### Network Issues

```python
# Symptoms: Connection timeouts, network errors
# Solution: Adjust network configuration

network_config = {
    'timeout': 60,                     # Increase timeout
    'retry_attempts': 5,               # More retries
    'connection_pool_size': 200,       # Larger pool
    'keep_alive': True,                # Enable keep-alive
    'max_retries': 3                   # Retry failed requests
}
```

### Debug Mode

```python
# Enable debug mode for detailed logging
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Enable AresProbe debug logging
logger = Logger()
logger.set_level('DEBUG')
```

### Performance Profiling

```python
# Enable performance profiling
from aresprobe.core.performance_optimizer import PerformanceOptimizer

optimizer = PerformanceOptimizer()
optimizer.start_monitoring()

# Your scanning code here...

# Get detailed performance report
report = optimizer.get_performance_report()
print(f"CPU Usage: {report['current_metrics']['cpu_usage']}%")
print(f"Memory Usage: {report['current_metrics']['memory_usage_mb']} MB")
print(f"Thread Count: {report['current_metrics']['thread_count']}")
```

### Log Analysis

```python
# Analyze logs for patterns
import re
from collections import Counter

def analyze_logs(log_file: str):
    with open(log_file, 'r') as f:
        logs = f.readlines()
    
    # Count error types
    errors = [line for line in logs if 'ERROR' in line]
    error_types = Counter()
    
    for error in errors:
        if 'timeout' in error.lower():
            error_types['timeout'] += 1
        elif 'connection' in error.lower():
            error_types['connection'] += 1
        elif 'memory' in error.lower():
            error_types['memory'] += 1
    
    print("Error Analysis:")
    for error_type, count in error_types.most_common():
        print(f"  {error_type}: {count}")
```

## Best Practices

### 1. Resource Management

- Always clean up resources after scanning
- Use context managers for automatic cleanup
- Monitor memory usage during long scans
- Implement proper error handling

### 2. Performance Optimization

- Use appropriate thread counts for your system
- Enable caching for repeated operations
- Monitor and adjust configuration based on performance
- Use async operations for I/O-bound tasks

### 3. Security Considerations

- Never run destructive tests on production systems
- Use proper authentication and authorization
- Implement rate limiting to avoid overwhelming targets
- Log all activities for audit purposes

### 4. Configuration Management

- Use environment variables for sensitive settings
- Implement configuration validation
- Document all custom configurations
- Version control your configuration files

### 5. Monitoring and Alerting

- Set up performance monitoring
- Implement alerting for critical issues
- Log all scanning activities
- Generate regular performance reports
