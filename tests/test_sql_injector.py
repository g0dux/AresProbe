"""
Unit tests for SQL Injector module
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import requests

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from aresprobe.core.sql_injector import SuperSQLInjector, SQLInjectionType, DatabaseType
from aresprobe.core.logger import Logger


class TestSuperSQLInjector(unittest.TestCase):
    """Test cases for SuperSQLInjector class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.logger = Logger()
        self.injector = SuperSQLInjector(self.logger)
        self.mock_config = Mock()
        self.mock_config.timeout = 30
        self.mock_config.headers = {}
        self.mock_config.cookies = {}
        self.mock_config.auth = None
        self.mock_config.verify_ssl = False
        self.mock_config.follow_redirects = True
    
    def test_initialization(self):
        """Test SQL injector initialization"""
        self.assertIsNotNone(self.injector)
        self.assertIsNotNone(self.injector.logger)
        self.assertIsNotNone(self.injector.session)
        self.assertEqual(len(self.injector.payloads), 7)  # 7 injection types
    
    def test_load_enhanced_payloads(self):
        """Test payload loading functionality"""
        payloads = self.injector._load_enhanced_payloads()
        
        # Check that all injection types have payloads
        self.assertIn(SQLInjectionType.BOOLEAN_BLIND, payloads)
        self.assertIn(SQLInjectionType.TIME_BASED, payloads)
        self.assertIn(SQLInjectionType.UNION_BASED, payloads)
        self.assertIn(SQLInjectionType.ERROR_BASED, payloads)
        self.assertIn(SQLInjectionType.STACKED_QUERIES, payloads)
        self.assertIn(SQLInjectionType.POLYMORPHIC, payloads)
        self.assertIn(SQLInjectionType.AI_POWERED, payloads)
        
        # Check that payloads are not empty
        for injection_type, payload_list in payloads.items():
            self.assertGreater(len(payload_list), 0)
    
    @patch('aresprobe.core.sql_injector.requests.Session.get')
    def test_determine_column_count_robust(self, mock_get):
        """Test robust column count determination"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "No error"
        mock_get.return_value = mock_response
        
        result = self.injector._determine_column_count_robust(
            "http://test.com?id=1", "id", "1", self.mock_config
        )
        
        # Should return 0 since no error is detected
        self.assertEqual(result, 0)
    
    @patch('aresprobe.core.sql_injector.requests.Session.get')
    def test_identify_vulnerable_columns_robust(self, mock_get):
        """Test vulnerable column identification"""
        # Mock response with test string
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "test"
        mock_get.return_value = mock_response
        
        result = self.injector._identify_vulnerable_columns_robust(
            "http://test.com?id=1", "id", "1", 3, self.mock_config
        )
        
        # Should identify column 1 as vulnerable
        self.assertIn(1, result)
    
    def test_build_test_url_with_payload(self):
        """Test URL building with payload"""
        url = "http://test.com?id=1&name=admin"
        param_name = "id"
        param_value = "1"
        payload = "' OR 1=1--"
        
        result = self.injector._build_test_url_with_payload(
            url, param_name, param_value, payload
        )
        
        self.assertIn("id=1'%20OR%201%3D1--", result)
        self.assertIn("name=admin", result)
    
    def test_detect_column_error(self):
        """Test column error detection"""
        # Test with error message
        error_text = "Unknown column 'test' in 'order clause'"
        self.assertTrue(self.injector._detect_column_error(error_text))
        
        # Test without error message
        normal_text = "Normal response content"
        self.assertFalse(self.injector._detect_column_error(normal_text))
    
    def test_parse_error_response(self):
        """Test error response parsing"""
        # Test with MySQL version
        mysql_error = "MySQL version 5.7.30"
        result = self.injector._parse_error_response(mysql_error)
        self.assertIn('version', result)
        
        # Test with database name
        db_error = "database 'testdb'"
        result = self.injector._parse_error_response(db_error)
        self.assertIn('database', result)
    
    @patch('aresprobe.core.sql_injector.requests.Session.get')
    def test_send_request_success(self, mock_get):
        """Test successful request sending"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = self.injector._send_request("http://test.com", self.mock_config)
        
        self.assertEqual(result, mock_response)
        mock_get.assert_called_once()
    
    @patch('aresprobe.core.sql_injector.requests.Session.get')
    def test_send_request_timeout(self, mock_get):
        """Test request timeout handling"""
        mock_get.side_effect = requests.exceptions.Timeout()
        
        result = self.injector._send_request("http://test.com", self.mock_config)
        
        self.assertIsNone(result)
        self.assertEqual(mock_get.call_count, 3)  # 3 retry attempts
    
    @patch('aresprobe.core.sql_injector.requests.Session.get')
    def test_send_request_connection_error(self, mock_get):
        """Test connection error handling"""
        mock_get.side_effect = requests.exceptions.ConnectionError()
        
        result = self.injector._send_request("http://test.com", self.mock_config)
        
        self.assertIsNone(result)
        self.assertEqual(mock_get.call_count, 3)  # 3 retry attempts
    
    def test_build_column_payload(self):
        """Test column payload building"""
        result = self.injector._build_column_payload(2, "version()", 3)
        expected = "NULL,version(),NULL"
        self.assertEqual(result, expected)
    
    def test_analyze_boolean_response(self):
        """Test boolean response analysis"""
        # Mock response with SQL error
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "mysql_fetch_array() error"
        
        payload = Mock()
        payload.injection_type = SQLInjectionType.BOOLEAN_BLIND
        
        result = self.injector._analyze_boolean_response(mock_response, payload)
        self.assertTrue(result)
    
    def test_analyze_time_response(self):
        """Test time-based response analysis"""
        mock_response = Mock()
        payload = Mock()
        payload.injection_type = SQLInjectionType.TIME_BASED
        
        # Test with sufficient delay
        result = self.injector._analyze_time_response(mock_response, payload, 5.5)
        self.assertTrue(result)
        
        # Test with insufficient delay
        result = self.injector._analyze_time_response(mock_response, payload, 2.0)
        self.assertFalse(result)
    
    def test_analyze_union_response(self):
        """Test UNION response analysis"""
        # Mock response with UNION error
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "mysql_fetch_array() error"
        
        payload = Mock()
        payload.injection_type = SQLInjectionType.UNION_BASED
        
        result = self.injector._analyze_union_response(mock_response, payload)
        self.assertTrue(result)
    
    def test_analyze_error_response(self):
        """Test error-based response analysis"""
        # Mock response with SQL error
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "SQL syntax error near 'test'"
        
        payload = Mock()
        payload.injection_type = SQLInjectionType.ERROR_BASED
        
        result = self.injector._analyze_error_response(mock_response, payload)
        self.assertTrue(result)
    
    def test_analyze_stacked_response(self):
        """Test stacked queries response analysis"""
        # Mock response with non-200 status
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        
        payload = Mock()
        payload.injection_type = SQLInjectionType.STACKED_QUERIES
        
        result = self.injector._analyze_stacked_response(mock_response, payload)
        self.assertTrue(result)
    
    @patch('aresprobe.core.sql_injector.requests.Session.get')
    def test_basic_sql_test(self, mock_get):
        """Test basic SQL injection testing"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "mysql_fetch_array() error"
        mock_get.return_value = mock_response
        
        injection_points = [{'name': 'id', 'value': '1'}]
        result = self.injector._basic_sql_test(
            "http://test.com?id=1", injection_points, self.mock_config
        )
        
        self.assertIn('vulnerabilities', result)
        self.assertIn('total_tests', result)
        self.assertIn('successful_tests', result)
        self.assertGreater(result['total_tests'], 0)
    
    def test_detect_basic_vulnerability(self):
        """Test basic vulnerability detection"""
        # Mock response with SQL error
        mock_response = Mock()
        mock_response.text = "mysql_fetch_array() error"
        
        result = self.injector._detect_basic_vulnerability(mock_response, "' OR 1=1--")
        self.assertTrue(result)
        
        # Mock response without error
        mock_response.text = "Normal response"
        result = self.injector._detect_basic_vulnerability(mock_response, "' OR 1=1--")
        self.assertFalse(result)


class TestSQLInjectionTypes(unittest.TestCase):
    """Test cases for SQL injection types"""
    
    def test_sql_injection_type_enum(self):
        """Test SQL injection type enumeration"""
        self.assertEqual(SQLInjectionType.BOOLEAN_BLIND.value, "boolean_blind")
        self.assertEqual(SQLInjectionType.TIME_BASED.value, "time_based")
        self.assertEqual(SQLInjectionType.UNION_BASED.value, "union_based")
        self.assertEqual(SQLInjectionType.ERROR_BASED.value, "error_based")
        self.assertEqual(SQLInjectionType.STACKED_QUERIES.value, "stacked_queries")
        self.assertEqual(SQLInjectionType.POLYMORPHIC.value, "polymorphic")
        self.assertEqual(SQLInjectionType.AI_POWERED.value, "ai_powered")
        self.assertEqual(SQLInjectionType.CONTEXT_AWARE.value, "context_aware")
    
    def test_database_type_enum(self):
        """Test database type enumeration"""
        self.assertEqual(DatabaseType.MYSQL.value, "mysql")
        self.assertEqual(DatabaseType.POSTGRESQL.value, "postgresql")
        self.assertEqual(DatabaseType.MSSQL.value, "mssql")
        self.assertEqual(DatabaseType.ORACLE.value, "oracle")
        self.assertEqual(DatabaseType.SQLITE.value, "sqlite")
        self.assertEqual(DatabaseType.UNKNOWN.value, "unknown")


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestSuperSQLInjector))
    test_suite.addTest(unittest.makeSuite(TestSQLInjectionTypes))
    
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
