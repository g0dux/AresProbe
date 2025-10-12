"""
Unit tests for AresProbe Engine
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aresprobe.core.engine import AresEngine, ScanConfig, ScanType
from aresprobe.core.logger import Logger


class TestAresEngine(unittest.TestCase):
    """Test cases for AresEngine class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.logger = Logger()
        self.engine = AresEngine()
    
    def test_initialization(self):
        """Test engine initialization"""
        self.assertIsNotNone(self.engine)
        self.assertIsNotNone(self.engine.logger)
        self.assertIsNotNone(self.engine.session_manager)
        self.assertIsNotNone(self.engine.scanner)
        self.assertIsNotNone(self.engine.sql_injector)
        self.assertIsNotNone(self.engine.ai_engine)
        self.assertIsNotNone(self.engine.plugin_manager)
        self.assertIsNotNone(self.engine.cache_manager)
        self.assertIsNotNone(self.engine.report_generator)
    
    @patch('aresprobe.core.engine.SessionManager.initialize')
    @patch('aresprobe.core.engine.PluginManager.initialize')
    @patch('aresprobe.core.engine.CacheManager.load_from_disk')
    def test_initialize_success(self, mock_cache_load, mock_plugin_init, mock_session_init):
        """Test successful engine initialization"""
        mock_session_init.return_value = True
        mock_plugin_init.return_value = True
        mock_cache_load.return_value = True
        
        result = self.engine.initialize()
        self.assertTrue(result)
    
    @patch('aresprobe.core.engine.SessionManager.initialize')
    def test_initialize_failure(self, mock_session_init):
        """Test engine initialization failure"""
        mock_session_init.side_effect = Exception("Initialization failed")
        
        result = self.engine.initialize()
        self.assertFalse(result)
    
    @patch('aresprobe.core.engine.ProxyServer')
    def test_start_proxy_success(self, mock_proxy_class):
        """Test successful proxy start"""
        mock_proxy = Mock()
        mock_proxy_class.return_value = mock_proxy
        
        result = self.engine.start_proxy(8080)
        self.assertTrue(result)
        mock_proxy.start.assert_called_once()
    
    @patch('aresprobe.core.engine.ProxyServer')
    def test_start_proxy_failure(self, mock_proxy_class):
        """Test proxy start failure"""
        mock_proxy_class.side_effect = Exception("Proxy start failed")
        
        result = self.engine.start_proxy(8080)
        self.assertFalse(result)
    
    def test_stop_proxy(self):
        """Test proxy stop"""
        # Test with no proxy running
        self.engine.stop_proxy()  # Should not raise exception
        
        # Test with proxy running
        mock_proxy = Mock()
        self.engine.proxy_server = mock_proxy
        self.engine.stop_proxy()
        mock_proxy.stop.assert_called_once()
    
    def test_run_scan_config_validation(self):
        """Test scan configuration validation"""
        # Test with valid config
        config = ScanConfig(
            target_url="http://test.com",
            scan_types=[ScanType.SQL_INJECTION]
        )
        
        self.assertEqual(config.target_url, "http://test.com")
        self.assertIn(ScanType.SQL_INJECTION, config.scan_types)
        self.assertTrue(config.proxy_enabled)
        self.assertEqual(config.proxy_port, 8080)
        self.assertEqual(config.threads, 10)
        self.assertEqual(config.timeout, 30)
    
    @patch('aresprobe.core.engine.AresEngine.start_proxy')
    @patch('aresprobe.core.engine.AresEngine.stop_proxy')
    @patch('aresprobe.core.sql_injector.SuperSQLInjector.scan_target')
    def test_run_scan_sql_injection(self, mock_sql_scan, mock_stop_proxy, mock_start_proxy):
        """Test SQL injection scan execution"""
        # Mock SQL injection results
        mock_sql_scan.return_value = {
            'vulnerabilities': [{'type': 'SQL_INJECTION', 'severity': 'HIGH'}],
            'scan_time': 1.5,
            'total_tests': 10,
            'successful_tests': 1
        }
        
        config = ScanConfig(
            target_url="http://test.com?id=1",
            scan_types=[ScanType.SQL_INJECTION],
            proxy_enabled=True
        )
        
        result = self.engine.run_scan(config)
        
        self.assertEqual(result['target'], "http://test.com?id=1")
        self.assertIn('sql_injection', result['results'])
        self.assertEqual(result['status'], 'completed')
        mock_start_proxy.assert_called_once()
        mock_stop_proxy.assert_called_once()
    
    @patch('aresprobe.core.engine.AresEngine.start_proxy')
    @patch('aresprobe.core.engine.AresEngine.stop_proxy')
    @patch('aresprobe.core.scanner.VulnerabilityScanner.scan_xss')
    def test_run_scan_xss(self, mock_xss_scan, mock_stop_proxy, mock_start_proxy):
        """Test XSS scan execution"""
        # Mock XSS scan results
        mock_xss_scan.return_value = {
            'vulnerabilities': [{'type': 'XSS', 'severity': 'MEDIUM'}],
            'scan_time': 1.0,
            'total_tests': 5,
            'successful_tests': 1
        }
        
        config = ScanConfig(
            target_url="http://test.com?name=admin",
            scan_types=[ScanType.XSS],
            proxy_enabled=False
        )
        
        result = self.engine.run_scan(config)
        
        self.assertEqual(result['target'], "http://test.com?name=admin")
        self.assertIn('xss', result['results'])
        self.assertEqual(result['status'], 'completed')
        mock_start_proxy.assert_not_called()
        mock_stop_proxy.assert_not_called()
    
    @patch('aresprobe.core.engine.AresEngine._run_comprehensive_scan')
    def test_run_scan_comprehensive(self, mock_comprehensive_scan):
        """Test comprehensive scan execution"""
        # Mock comprehensive scan results
        mock_comprehensive_scan.return_value = {
            'sql_injection': {'vulnerabilities': []},
            'xss': {'vulnerabilities': []},
            'directory_traversal': {'vulnerabilities': []}
        }
        
        config = ScanConfig(
            target_url="http://test.com",
            scan_types=[ScanType.COMPREHENSIVE]
        )
        
        result = self.engine.run_scan(config)
        
        self.assertEqual(result['target'], "http://test.com")
        self.assertIn('comprehensive', result['results'])
        self.assertEqual(result['status'], 'completed')
    
    def test_stop_scan(self):
        """Test scan stopping"""
        self.engine.is_running = True
        self.engine.stop_scan()
        self.assertFalse(self.engine.is_running)
    
    def test_get_scan_results(self):
        """Test getting scan results"""
        # Test with no results
        results = self.engine.get_scan_results()
        self.assertEqual(results, {})
        
        # Test with results
        test_results = {'target': 'http://test.com', 'status': 'completed'}
        self.engine.scan_results = test_results
        results = self.engine.get_scan_results()
        self.assertEqual(results, test_results)
    
    def test_generate_report_no_results(self):
        """Test report generation with no results"""
        result = self.engine.generate_report()
        self.assertEqual(result, "No scan results available")
    
    def test_generate_report_with_results(self):
        """Test report generation with results"""
        self.engine.scan_results = {
            'target': 'http://test.com',
            'scan_types': ['sql_injection'],
            'duration': 5.5,
            'status': 'completed',
            'results': {
                'sql_injection': {
                    'vulnerabilities': [{'type': 'SQL_INJECTION', 'severity': 'HIGH'}]
                }
            }
        }
        
        result = self.engine.generate_report()
        self.assertIn("ARESPROBE SECURITY SCAN REPORT", result)
        self.assertIn("http://test.com", result)
        self.assertIn("sql_injection", result)
    
    @patch('builtins.open', create=True)
    def test_generate_report_to_file(self, mock_open):
        """Test report generation to file"""
        self.engine.scan_results = {
            'target': 'http://test.com',
            'scan_types': ['sql_injection'],
            'duration': 5.5,
            'status': 'completed',
            'results': {}
        }
        
        result = self.engine.generate_report("test_report.txt")
        mock_open.assert_called_once_with("test_report.txt", 'w', encoding='utf-8')
    
    def test_cleanup(self):
        """Test engine cleanup"""
        # Mock components
        self.engine.session_manager = Mock()
        self.engine.plugin_manager = Mock()
        self.engine.cache_manager = Mock()
        
        self.engine.cleanup()
        
        self.engine.session_manager.cleanup.assert_called_once()
        self.engine.plugin_manager.cleanup.assert_called_once()
        self.engine.cache_manager.save_to_disk.assert_called_once()
    
    def test_format_report(self):
        """Test report formatting"""
        self.engine.scan_results = {
            'target': 'http://test.com',
            'scan_types': ['sql_injection', 'xss'],
            'duration': 10.5,
            'status': 'completed',
            'results': {
                'sql_injection': {
                    'vulnerabilities': [{'type': 'SQL_INJECTION', 'severity': 'HIGH'}],
                    'scan_time': 5.0
                },
                'xss': {
                    'vulnerabilities': [{'type': 'XSS', 'severity': 'MEDIUM'}],
                    'scan_time': 3.0
                }
            }
        }
        
        result = self.engine._format_report()
        
        self.assertIn("ARESPROBE SECURITY SCAN REPORT", result)
        self.assertIn("http://test.com", result)
        self.assertIn("sql_injection, xss", result)
        self.assertIn("10.50 seconds", result)
        self.assertIn("completed", result)
        self.assertIn("SQL_INJECTION SCAN RESULTS", result)
        self.assertIn("XSS SCAN RESULTS", result)


class TestScanConfig(unittest.TestCase):
    """Test cases for ScanConfig class"""
    
    def test_scan_config_defaults(self):
        """Test ScanConfig default values"""
        config = ScanConfig(
            target_url="http://test.com",
            scan_types=[ScanType.SQL_INJECTION]
        )
        
        self.assertEqual(config.target_url, "http://test.com")
        self.assertIn(ScanType.SQL_INJECTION, config.scan_types)
        self.assertTrue(config.proxy_enabled)
        self.assertEqual(config.proxy_port, 8080)
        self.assertEqual(config.threads, 10)
        self.assertEqual(config.timeout, 30)
        self.assertEqual(config.user_agent, "AresProbe/1.0")
        self.assertIsNone(config.cookies)
        self.assertIsNone(config.headers)
        self.assertIsNone(config.auth)
        self.assertTrue(config.follow_redirects)
        self.assertFalse(config.verify_ssl)
    
    def test_scan_config_custom_values(self):
        """Test ScanConfig with custom values"""
        config = ScanConfig(
            target_url="https://test.com",
            scan_types=[ScanType.XSS, ScanType.CSRF],
            proxy_enabled=False,
            proxy_port=9090,
            threads=20,
            timeout=60,
            user_agent="CustomAgent/1.0",
            cookies={"session": "abc123"},
            headers={"X-Custom": "value"},
            auth=("user", "pass"),
            follow_redirects=False,
            verify_ssl=True
        )
        
        self.assertEqual(config.target_url, "https://test.com")
        self.assertIn(ScanType.XSS, config.scan_types)
        self.assertIn(ScanType.CSRF, config.scan_types)
        self.assertFalse(config.proxy_enabled)
        self.assertEqual(config.proxy_port, 9090)
        self.assertEqual(config.threads, 20)
        self.assertEqual(config.timeout, 60)
        self.assertEqual(config.user_agent, "CustomAgent/1.0")
        self.assertEqual(config.cookies, {"session": "abc123"})
        self.assertEqual(config.headers, {"X-Custom": "value"})
        self.assertEqual(config.auth, ("user", "pass"))
        self.assertFalse(config.follow_redirects)
        self.assertTrue(config.verify_ssl)


class TestScanType(unittest.TestCase):
    """Test cases for ScanType enum"""
    
    def test_scan_type_values(self):
        """Test ScanType enum values"""
        self.assertEqual(ScanType.SQL_INJECTION.value, "sql_injection")
        self.assertEqual(ScanType.XSS.value, "xss")
        self.assertEqual(ScanType.CSRF.value, "csrf")
        self.assertEqual(ScanType.DIRECTORY_TRAVERSAL.value, "directory_traversal")
        self.assertEqual(ScanType.COMMAND_INJECTION.value, "command_injection")
        self.assertEqual(ScanType.XXE.value, "xxe")
        self.assertEqual(ScanType.SSRF.value, "ssrf")
        self.assertEqual(ScanType.FILE_UPLOAD.value, "file_upload")
        self.assertEqual(ScanType.AUTHENTICATION.value, "authentication")
        self.assertEqual(ScanType.AUTHORIZATION.value, "authorization")
        self.assertEqual(ScanType.COMPREHENSIVE.value, "comprehensive")


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestAresEngine))
    test_suite.addTest(unittest.makeSuite(TestScanConfig))
    test_suite.addTest(unittest.makeSuite(TestScanType))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*50}")
