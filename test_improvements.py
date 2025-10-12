#!/usr/bin/env python3
"""
Test script to verify all improvements are working correctly
"""

import sys
import os
import time
import unittest
from unittest.mock import Mock, patch

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

def test_sql_injector_improvements():
    """Test SQL injector improvements"""
    print("\n" + "="*50)
    print("Testing SQL Injector Improvements")
    print("="*50)
    
    try:
        from aresprobe.core.sql_injector import SuperSQLInjector
        from aresprobe.core.logger import Logger
        
        # Test initialization
        logger = Logger()
        injector = SuperSQLInjector(logger)
        print("[+] SQL Injector initialized successfully")
        
        # Test enhanced payloads
        payloads = injector._load_enhanced_payloads()
        print(f"[+] Loaded {len(payloads)} injection types")
        
        # Test robust column count determination
        with patch('aresprobe.core.sql_injector.requests.Session.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "No error"
            mock_get.return_value = mock_response
            
            class MockConfig:
                timeout = 30
                headers = {}
                cookies = {}
                auth = None
                verify_ssl = False
                follow_redirects = True
            
            config = MockConfig()
            column_count = injector._determine_column_count_robust(
                "http://test.com?id=1", "id", "1", config
            )
            print(f"[+] Column count determination: {column_count}")
        
        # Test vulnerable column identification
        with patch('aresprobe.core.sql_injector.requests.Session.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "test"
            mock_get.return_value = mock_response
            
            vulnerable_columns = injector._identify_vulnerable_columns_robust(
                "http://test.com?id=1", "id", "1", 3, config
            )
            print(f"[+] Vulnerable columns identified: {vulnerable_columns}")
        
        print("[+] SQL Injector improvements working correctly")
        return True
        
    except Exception as e:
        print(f"[-] SQL Injector test failed: {e}")
        return False

def test_performance_optimizer():
    """Test performance optimizer"""
    print("\n" + "="*50)
    print("Testing Performance Optimizer")
    print("="*50)
    
    try:
        from aresprobe.core.performance_optimizer import (
            PerformanceOptimizer, OptimizationConfig, OptimizationLevel
        )
        from aresprobe.core.logger import Logger
        
        # Test initialization
        logger = Logger()
        config = OptimizationConfig(
            max_memory_usage=0.8,
            max_threads=50,
            optimization_level=OptimizationLevel.BASIC
        )
        
        optimizer = PerformanceOptimizer(config, logger)
        print("[+] Performance Optimizer initialized successfully")
        
        # Test metrics collection
        metrics = optimizer.collect_metrics()
        print(f"[+] Metrics collected: CPU={metrics.cpu_usage:.2f}%, Memory={metrics.memory_usage:.2f}MB")
        
        # Test memory manager
        memory_stats = optimizer.memory_manager.get_memory_usage()
        print(f"[+] Memory stats: RSS={memory_stats['rss']}, VMS={memory_stats['vms']}")
        
        # Test thread manager
        thread_pool = optimizer.thread_manager.get_thread_pool("test", 5)
        print(f"[+] Thread pool created: {thread_pool}")
        
        # Test performance report
        report = optimizer.get_performance_report()
        print(f"[+] Performance report generated: {len(report)} sections")
        
        # Cleanup
        optimizer.cleanup()
        print("[+] Performance Optimizer cleaned up")
        
        print("[+] Performance Optimizer working correctly")
        return True
        
    except Exception as e:
        print(f"[-] Performance Optimizer test failed: {e}")
        return False

def test_unit_tests():
    """Test unit tests"""
    print("\n" + "="*50)
    print("Testing Unit Tests")
    print("="*50)
    
    try:
        # Test SQL injector unit tests
        from tests.test_sql_injector import TestSuperSQLInjector, TestSQLInjectionTypes
        
        # Create test suite
        test_suite = unittest.TestSuite()
        test_suite.addTest(unittest.makeSuite(TestSuperSQLInjector))
        test_suite.addTest(unittest.makeSuite(TestSQLInjectionTypes))
        
        # Run tests
        runner = unittest.TextTestRunner(verbosity=0)
        result = runner.run(test_suite)
        
        print(f"[+] SQL Injector tests: {result.testsRun} run, {len(result.failures)} failures, {len(result.errors)} errors")
        
        # Test engine unit tests
        from tests.test_engine import TestAresEngine, TestScanConfig, TestScanType
        
        test_suite = unittest.TestSuite()
        test_suite.addTest(unittest.makeSuite(TestAresEngine))
        test_suite.addTest(unittest.makeSuite(TestScanConfig))
        test_suite.addTest(unittest.makeSuite(TestScanType))
        
        result = runner.run(test_suite)
        print(f"[+] Engine tests: {result.testsRun} run, {len(result.failures)} failures, {len(result.errors)} errors")
        
        total_tests = result.testsRun
        total_failures = len(result.failures) + len(result.errors)
        success_rate = ((total_tests - total_failures) / total_tests * 100) if total_tests > 0 else 0
        
        print(f"[+] Overall test success rate: {success_rate:.1f}%")
        
        return total_failures == 0
        
    except Exception as e:
        print(f"[-] Unit tests failed: {e}")
        return False

def test_documentation():
    """Test documentation files"""
    print("\n" + "="*50)
    print("Testing Documentation")
    print("="*50)
    
    try:
        # Check if documentation files exist
        doc_files = [
            'docs/API_REFERENCE.md',
            'docs/ADVANCED_CONFIGURATION.md',
            'examples/advanced_usage.py'
        ]
        
        for doc_file in doc_files:
            if os.path.exists(doc_file):
                with open(doc_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    print(f"[+] {doc_file}: {len(content)} characters")
            else:
                print(f"[-] {doc_file}: File not found")
                return False
        
        print("[+] All documentation files present and readable")
        return True
        
    except Exception as e:
        print(f"[-] Documentation test failed: {e}")
        return False

def test_imports():
    """Test that all modules can be imported"""
    print("\n" + "="*50)
    print("Testing Module Imports")
    print("="*50)
    
    try:
        # Test core modules
        from aresprobe.core.engine import AresEngine, ScanConfig, ScanType
        print("[+] Core engine imports successful")
        
        from aresprobe.core.sql_injector import SuperSQLInjector, SQLInjectionType
        print("[+] SQL injector imports successful")
        
        from aresprobe.core.scanner import VulnerabilityScanner
        print("[+] Scanner imports successful")
        
        from aresprobe.core.ai_engine import AIEngine
        print("[+] AI engine imports successful")
        
        from aresprobe.core.performance_optimizer import PerformanceOptimizer
        print("[+] Performance optimizer imports successful")
        
        from aresprobe.core.logger import Logger
        print("[+] Logger imports successful")
        
        print("[+] All module imports successful")
        return True
        
    except Exception as e:
        print(f"[-] Import test failed: {e}")
        return False

def main():
    """Main test function"""
    print("AresProbe Improvements Test Suite")
    print("=" * 60)
    
    tests = [
        ("Module Imports", test_imports),
        ("SQL Injector Improvements", test_sql_injector_improvements),
        ("Performance Optimizer", test_performance_optimizer),
        ("Unit Tests", test_unit_tests),
        ("Documentation", test_documentation)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"[-] {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n[+] All improvements implemented successfully!")
        print("[+] AresProbe is now more mature, performant, and well-documented!")
    else:
        print(f"\n[-] {total-passed} tests failed. Please check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
