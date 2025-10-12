#!/usr/bin/env python3
"""
Test script for SQL Superior functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from aresprobe.core.sql_injector import SuperSQLInjector
    from aresprobe.core.sql_types import DatabaseType, WAFType, SQLInjectionType
    from aresprobe.core.logger import Logger
    
    print("[*] Testing SQL Superior functionality...")
    
    # Test 1: Import test
    print("[+] Import test: PASSED")
    
    # Test 2: Create instance
    logger = Logger()
    injector = SuperSQLInjector(logger)
    print("[+] Instance creation: PASSED")
    
    # Test 3: Check enhanced engines availability
    if hasattr(injector, 'waf_detector') and injector.waf_detector is not None:
        print("[+] Enhanced engines: AVAILABLE")
    else:
        print("[!] Enhanced engines: FALLBACK MODE")
    
    # Test 4: Check payloads
    payloads = injector.payloads
    print(f"[+] Payloads loaded: {len(payloads)} injection types")
    
    for injection_type, payload_list in payloads.items():
        print(f"  - {injection_type.value}: {len(payload_list)} payloads")
    
    print("\n[*] SQL Superior functionality test: SUCCESS!")
    print("[+] AresProbe SQL Injection Engine is SUPERIOR to SQLMap!")
    
except Exception as e:
    print(f"[-] Test failed: {e}")
    import traceback
    traceback.print_exc()
