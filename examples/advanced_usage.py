#!/usr/bin/env python3
"""
AresProbe Advanced Usage Examples
Comprehensive examples demonstrating all major features
"""

import asyncio
import time
import json
from typing import Dict, List, Any

# Import AresProbe modules
from aresprobe.core.engine import AresEngine, ScanConfig, ScanType
from aresprobe.core.sql_injector import SuperSQLInjector, SQLInjectionType
from aresprobe.core.scanner import VulnerabilityScanner
from aresprobe.core.ai_engine import AIEngine
from aresprobe.core.performance_optimizer import (
    PerformanceOptimizer, OptimizationConfig, OptimizationLevel
)
from aresprobe.core.logger import Logger


class AresProbeAdvancedExamples:
    """Advanced usage examples for AresProbe"""
    
    def __init__(self):
        self.logger = Logger()
        self.engine = AresEngine()
        self.optimizer = None
        
    def example_1_basic_scan(self):
        """Example 1: Basic security scan"""
        print("\n" + "="*60)
        print("EXAMPLE 1: Basic Security Scan")
        print("="*60)
        
        # Initialize engine
        if not self.engine.initialize():
            print("[-] Failed to initialize engine")
            return
        
        # Configure basic scan
        config = ScanConfig(
            target_url="http://testphp.vulnweb.com/artists.php?artist=1",
            scan_types=[ScanType.SQL_INJECTION, ScanType.XSS],
            threads=10,
            timeout=30
        )
        
        print(f"[*] Starting scan on: {config.target_url}")
        start_time = time.time()
        
        # Run scan
        results = self.engine.run_scan(config)
        
        scan_time = time.time() - start_time
        print(f"[+] Scan completed in {scan_time:.2f} seconds")
        
        # Display results
        self._display_scan_results(results)
        
        # Generate report
        report = self.engine.generate_report("example1_report.html")
        print(f"[+] Report saved to: example1_report.html")
    
    def example_2_advanced_sql_injection(self):
        """Example 2: Advanced SQL injection testing"""
        print("\n" + "="*60)
        print("EXAMPLE 2: Advanced SQL Injection Testing")
        print("="*60)
        
        # Initialize SQL injector
        injector = SuperSQLInjector(self.logger)
        
        # Test different injection types
        target_url = "http://testphp.vulnweb.com/artists.php?artist=1"
        
        # Create mock config
        class MockConfig:
            timeout = 30
            headers = {}
            cookies = {}
            auth = None
            verify_ssl = False
            follow_redirects = True
        
        config = MockConfig()
        
        print(f"[*] Testing SQL injection on: {target_url}")
        
        # Test superior scanning
        results = injector.scan_target_superior(target_url, config)
        
        if results.get('vulnerabilities'):
            print(f"[+] Found {len(results['vulnerabilities'])} vulnerabilities")
            
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"\nVulnerability {i}:")
                print(f"  Parameter: {vuln.get('parameter', 'N/A')}")
                print(f"  Payload: {vuln.get('payload', 'N/A')}")
                print(f"  Type: {vuln.get('injection_type', 'N/A')}")
                print(f"  Risk Level: {vuln.get('risk_level', 'N/A')}")
        else:
            print("[-] No SQL injection vulnerabilities found")
        
        # Test data extraction if vulnerabilities found
        if results.get('vulnerabilities'):
            print("\n[*] Attempting data extraction...")
            extraction_results = injector.extract_data(
                target_url, 
                results['vulnerabilities'][0].get('parameter', 'id'),
                "1",
                "union_based",
                config
            )
            
            if extraction_results.get('success'):
                print("[+] Data extraction successful")
                print(f"Database info: {extraction_results.get('database_info', {})}")
                print(f"Tables found: {extraction_results.get('tables', [])}")
            else:
                print("[-] Data extraction failed")
    
    def example_3_comprehensive_scan(self):
        """Example 3: Comprehensive multi-vector scan"""
        print("\n" + "="*60)
        print("EXAMPLE 3: Comprehensive Multi-Vector Scan")
        print("="*60)
        
        if not self.engine.initialize():
            print("[-] Failed to initialize engine")
            return
        
        # Configure comprehensive scan
        config = ScanConfig(
            target_url="http://testphp.vulnweb.com/",
            scan_types=[
                ScanType.SQL_INJECTION,
                ScanType.XSS,
                ScanType.DIRECTORY_TRAVERSAL,
                ScanType.COMMAND_INJECTION,
                ScanType.XXE,
                ScanType.SSRF
            ],
            proxy_enabled=True,
            threads=20,
            timeout=60
        )
        
        print(f"[*] Starting comprehensive scan on: {config.target_url}")
        print(f"[*] Scan types: {[t.value for t in config.scan_types]}")
        
        start_time = time.time()
        results = self.engine.run_scan(config)
        scan_time = time.time() - start_time
        
        print(f"[+] Comprehensive scan completed in {scan_time:.2f} seconds")
        
        # Analyze results by vulnerability type
        total_vulnerabilities = 0
        vulnerability_summary = {}
        
        for scan_type, scan_results in results.get('results', {}).items():
            vulns = scan_results.get('vulnerabilities', [])
            vulnerability_summary[scan_type] = len(vulns)
            total_vulnerabilities += len(vulns)
            
            if vulns:
                print(f"\n{scan_type.upper()} Vulnerabilities ({len(vulns)}):")
                for i, vuln in enumerate(vulns[:3], 1):  # Show first 3
                    print(f"  {i}. {vuln.get('description', 'N/A')}")
                    print(f"     Severity: {vuln.get('severity', 'N/A')}")
                    print(f"     Parameter: {vuln.get('parameter', 'N/A')}")
        
        print(f"\n[+] Total vulnerabilities found: {total_vulnerabilities}")
        
        # Generate detailed report
        report = self.engine.generate_report("comprehensive_scan_report.html")
        print(f"[+] Detailed report saved to: comprehensive_scan_report.html")
    
    def example_4_ai_powered_analysis(self):
        """Example 4: AI-powered vulnerability analysis"""
        print("\n" + "="*60)
        print("EXAMPLE 4: AI-Powered Vulnerability Analysis")
        print("="*60)
        
        # Initialize AI engine
        ai_engine = AIEngine(self.logger)
        
        # Sample response data
        response_text = """
        <html>
        <head><title>Search Results</title></head>
        <body>
        <h1>Search Results</h1>
        <p>Results for: admin' OR 1=1--</p>
        <table>
        <tr><td>ID</td><td>Name</td><td>Email</td></tr>
        <tr><td>1</td><td>admin</td><td>admin@example.com</td></tr>
        <tr><td>2</td><td>user</td><td>user@example.com</td></tr>
        </table>
        <p>mysql_fetch_array() error in /var/www/search.php on line 15</p>
        </body>
        </html>
        """
        
        response_headers = {
            'Content-Type': 'text/html',
            'Server': 'Apache/2.4.41',
            'X-Powered-By': 'PHP/7.4.3'
        }
        
        print("[*] Analyzing response with AI engine...")
        
        # Analyze response
        analysis_results = ai_engine.analyze_response(
            response_text, 
            response_headers, 
            "http://example.com/search.php?q=admin' OR 1=1--"
        )
        
        if analysis_results:
            print("[+] AI analysis completed")
            for result in analysis_results:
                print(f"Vulnerability Type: {result.get('vulnerability_type', 'N/A')}")
                print(f"Confidence: {result.get('confidence', 0):.2f}")
                print(f"Threat Level: {result.get('threat_level', 'N/A')}")
                print(f"Description: {result.get('description', 'N/A')}")
                print(f"Recommendations: {result.get('recommendations', [])}")
                print("-" * 40)
        else:
            print("[-] No vulnerabilities detected by AI")
        
        # Generate smart payloads
        print("\n[*] Generating smart payloads...")
        context = {
            'database_type': 'mysql',
            'parameter_type': 'string',
            'waf_detected': False
        }
        
        payloads = ai_engine.generate_smart_payloads(
            'sql_injection', 
            context, 
            count=5
        )
        
        if payloads:
            print("[+] Generated smart payloads:")
            for i, payload in enumerate(payloads, 1):
                print(f"  {i}. {payload}")
        else:
            print("[-] No payloads generated")
    
    def example_5_performance_optimization(self):
        """Example 5: Performance optimization and monitoring"""
        print("\n" + "="*60)
        print("EXAMPLE 5: Performance Optimization and Monitoring")
        print("="*60)
        
        # Configure performance optimization
        config = OptimizationConfig(
            max_memory_usage=0.8,
            max_threads=100,
            optimization_level=OptimizationLevel.AGGRESSIVE,
            enable_profiling=True,
            enable_memory_tracking=True
        )
        
        # Initialize optimizer
        self.optimizer = PerformanceOptimizer(config, self.logger)
        self.optimizer.start_monitoring()
        
        print("[*] Performance monitoring started")
        
        # Simulate some operations
        print("[*] Simulating operations...")
        for i in range(100):
            self.optimizer.track_operation(f"operation_{i}")
            self.optimizer.track_response_time(0.1 + (i % 10) * 0.01)
            self.optimizer.track_request()
            
            if i % 20 == 0:
                time.sleep(0.1)  # Simulate some processing time
        
        # Get performance report
        print("\n[*] Collecting performance metrics...")
        report = self.optimizer.get_performance_report()
        
        print("\n[+] Performance Report:")
        print(f"CPU Usage: {report['current_metrics']['cpu_usage']:.2f}%")
        print(f"Memory Usage: {report['current_metrics']['memory_usage_mb']:.2f} MB")
        print(f"Available Memory: {report['current_metrics']['memory_available_mb']:.2f} MB")
        print(f"Thread Count: {report['current_metrics']['thread_count']}")
        print(f"Active Connections: {report['current_metrics']['active_connections']}")
        print(f"Average Response Time: {report['current_metrics']['response_time_avg']:.3f}s")
        print(f"Requests per Second: {report['current_metrics']['requests_per_second']:.2f}")
        
        print(f"\nStatistics:")
        print(f"Total Requests: {report['statistics']['total_requests']}")
        print(f"Total Operations: {report['statistics']['total_operations']}")
        print(f"Uptime: {report['statistics']['uptime_seconds']:.2f}s")
        print(f"Metrics Collected: {report['statistics']['metrics_collected']}")
        
        # Stop monitoring
        self.optimizer.stop_monitoring()
        print("\n[+] Performance monitoring stopped")
    
    def example_6_custom_scan_configuration(self):
        """Example 6: Custom scan configuration and advanced options"""
        print("\n" + "="*60)
        print("EXAMPLE 6: Custom Scan Configuration")
        print("="*60)
        
        if not self.engine.initialize():
            print("[-] Failed to initialize engine")
            return
        
        # Custom headers and cookies
        custom_headers = {
            'User-Agent': 'AresProbe-Custom/1.0',
            'X-Custom-Header': 'CustomValue',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        custom_cookies = {
            'session_id': 'abc123def456',
            'csrf_token': 'xyz789',
            'user_pref': 'dark_mode'
        }
        
        # Advanced scan configuration
        config = ScanConfig(
            target_url="http://testphp.vulnweb.com/login.php",
            scan_types=[ScanType.SQL_INJECTION, ScanType.XSS, ScanType.AUTHENTICATION],
            proxy_enabled=False,  # Disable proxy for this scan
            proxy_port=9090,
            threads=30,
            timeout=45,
            user_agent="AresProbe-Advanced/1.0",
            cookies=custom_cookies,
            headers=custom_headers,
            auth=("admin", "password"),  # Basic auth
            follow_redirects=True,
            verify_ssl=False
        )
        
        print(f"[*] Starting custom scan with advanced configuration")
        print(f"Target: {config.target_url}")
        print(f"Threads: {config.threads}")
        print(f"Timeout: {config.timeout}s")
        print(f"Custom Headers: {len(custom_headers)}")
        print(f"Custom Cookies: {len(custom_cookies)}")
        print(f"Authentication: {'Yes' if config.auth else 'No'}")
        
        start_time = time.time()
        results = self.engine.run_scan(config)
        scan_time = time.time() - start_time
        
        print(f"\n[+] Custom scan completed in {scan_time:.2f} seconds")
        
        # Display results
        self._display_scan_results(results)
    
    def example_7_batch_scanning(self):
        """Example 7: Batch scanning multiple targets"""
        print("\n" + "="*60)
        print("EXAMPLE 7: Batch Scanning Multiple Targets")
        print("="*60)
        
        if not self.engine.initialize():
            print("[-] Failed to initialize engine")
            return
        
        # List of targets to scan
        targets = [
            "http://testphp.vulnweb.com/artists.php?artist=1",
            "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "http://testphp.vulnweb.com/userinfo.php",
            "http://testphp.vulnweb.com/login.php",
            "http://testphp.vulnweb.com/search.php"
        ]
        
        print(f"[*] Batch scanning {len(targets)} targets")
        
        batch_results = {}
        total_vulnerabilities = 0
        
        for i, target in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] Scanning: {target}")
            
            config = ScanConfig(
                target_url=target,
                scan_types=[ScanType.SQL_INJECTION, ScanType.XSS],
                threads=15,
                timeout=30
            )
            
            start_time = time.time()
            results = self.engine.run_scan(config)
            scan_time = time.time() - start_time
            
            # Count vulnerabilities
            vuln_count = 0
            for scan_type, scan_results in results.get('results', {}).items():
                vuln_count += len(scan_results.get('vulnerabilities', []))
            
            batch_results[target] = {
                'vulnerabilities': vuln_count,
                'scan_time': scan_time,
                'status': results.get('status', 'unknown')
            }
            
            total_vulnerabilities += vuln_count
            print(f"  Vulnerabilities: {vuln_count}")
            print(f"  Scan Time: {scan_time:.2f}s")
            print(f"  Status: {results.get('status', 'unknown')}")
        
        # Summary
        print(f"\n[+] Batch scan completed")
        print(f"Total targets: {len(targets)}")
        print(f"Total vulnerabilities: {total_vulnerabilities}")
        print(f"Average vulnerabilities per target: {total_vulnerabilities / len(targets):.2f}")
        
        # Save batch results
        with open("batch_scan_results.json", "w") as f:
            json.dump(batch_results, f, indent=2)
        print(f"[+] Batch results saved to: batch_scan_results.json")
    
    def example_8_async_scanning(self):
        """Example 8: Asynchronous scanning"""
        print("\n" + "="*60)
        print("EXAMPLE 8: Asynchronous Scanning")
        print("="*60)
        
        async def async_scan_target(target_url: str, scan_types: List[ScanType]) -> Dict[str, Any]:
            """Async scan function"""
            if not self.engine.initialize():
                return {'error': 'Failed to initialize engine'}
            
            config = ScanConfig(
                target_url=target_url,
                scan_types=scan_types,
                threads=20,
                timeout=30
            )
            
            # Simulate async operation
            await asyncio.sleep(0.1)
            
            results = self.engine.run_scan(config)
            return results
        
        async def run_async_scans():
            """Run multiple scans asynchronously"""
            targets = [
                ("http://testphp.vulnweb.com/artists.php?artist=1", [ScanType.SQL_INJECTION]),
                ("http://testphp.vulnweb.com/listproducts.php?cat=1", [ScanType.XSS]),
                ("http://testphp.vulnweb.com/userinfo.php", [ScanType.SQL_INJECTION, ScanType.XSS])
            ]
            
            print(f"[*] Starting {len(targets)} async scans")
            
            # Create tasks
            tasks = [
                async_scan_target(target, scan_types) 
                for target, scan_types in targets
            ]
            
            # Run all scans concurrently
            start_time = time.time()
            results = await asyncio.gather(*tasks)
            total_time = time.time() - start_time
            
            print(f"[+] Async scans completed in {total_time:.2f} seconds")
            
            # Display results
            for i, (target, result) in enumerate(zip(targets, results), 1):
                print(f"\nScan {i}: {target[0]}")
                if 'error' in result:
                    print(f"  Error: {result['error']}")
                else:
                    vuln_count = sum(
                        len(scan_results.get('vulnerabilities', []))
                        for scan_results in result.get('results', {}).values()
                    )
                    print(f"  Vulnerabilities: {vuln_count}")
                    print(f"  Status: {result.get('status', 'unknown')}")
        
        # Run async scans
        asyncio.run(run_async_scans())
    
    def _display_scan_results(self, results: Dict[str, Any]):
        """Display scan results in a formatted way"""
        print(f"\n[+] Scan Results:")
        print(f"Target: {results.get('target', 'N/A')}")
        print(f"Status: {results.get('status', 'N/A')}")
        print(f"Duration: {results.get('duration', 0):.2f} seconds")
        
        scan_results = results.get('results', {})
        if scan_results:
            print(f"\nVulnerability Summary:")
            for scan_type, scan_data in scan_results.items():
                vulns = scan_data.get('vulnerabilities', [])
                print(f"  {scan_type}: {len(vulns)} vulnerabilities")
                
                if vulns:
                    for i, vuln in enumerate(vulns[:2], 1):  # Show first 2
                        print(f"    {i}. {vuln.get('description', 'N/A')}")
                        print(f"       Severity: {vuln.get('severity', 'N/A')}")
        else:
            print("No scan results available")
    
    def cleanup(self):
        """Cleanup resources"""
        if self.engine:
            self.engine.cleanup()
        if self.optimizer:
            self.optimizer.cleanup()


def main():
    """Main function to run all examples"""
    print("AresProbe Advanced Usage Examples")
    print("=" * 60)
    
    examples = AresProbeAdvancedExamples()
    
    try:
        # Run all examples
        examples.example_1_basic_scan()
        examples.example_2_advanced_sql_injection()
        examples.example_3_comprehensive_scan()
        examples.example_4_ai_powered_analysis()
        examples.example_5_performance_optimization()
        examples.example_6_custom_scan_configuration()
        examples.example_7_batch_scanning()
        examples.example_8_async_scanning()
        
        print("\n" + "="*60)
        print("All examples completed successfully!")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\n[!] Examples interrupted by user")
    except Exception as e:
        print(f"\n[-] Error running examples: {e}")
    finally:
        examples.cleanup()


if __name__ == "__main__":
    main()
