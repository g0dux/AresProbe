#!/usr/bin/env python3
"""
Simple test script for Advanced Hash Cracker
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aresprobe', 'core'))

# Import directly from the module
from advanced_hash_cracker import AdvancedHashCracker, HashAlgorithm

def test_hash_cracker():
    """Test the advanced hash cracker"""
    print("[*] Testing Advanced Hash Cracker...")
    
    # Create hash cracker instance
    cracker = AdvancedHashCracker()
    
    # Test basic functionality
    print(f"[+] Available algorithms: {len(cracker.get_available_algorithms())}")
    print(f"[+] Attack types: {cracker.get_attack_types()}")
    print(f"[+] Wordlists: {list(cracker.get_wordlists().keys())}")
    
    # Test hash detection
    test_hashes = [
        "5d41402abc4b2a76b9719d911017c592",  # MD5 of "hello"
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",  # SHA1 of "hello"
        "2cf24dba4f21b87e",  # SHA256 of "hello" (first 16 chars)
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA256 of ""
    ]
    
    for hash_value in test_hashes:
        detected_types = cracker.detect_hash_type(hash_value)
        print(f"[+] Hash {hash_value[:20]}... detected as: {[t.value for t in detected_types]}")
    
    # Test hash cracking with a simple MD5 hash
    print("\n[*] Testing hash cracking...")
    test_hash = "5d41402abc4b2a76b9719d911017c592"  # MD5 of "hello"
    detected_types = cracker.detect_hash_type(test_hash)
    
    if detected_types:
        algorithm = detected_types[0]
        print(f"[+] Attempting to crack {algorithm.value} hash: {test_hash}")
        
        # Try dictionary attack
        result = cracker.crack_hash(test_hash, algorithm, "dictionary", "common_passwords")
        
        if result and result.success:
            print(f"[+] SUCCESS! Password found: {result.plaintext}")
            print(f"[+] Method: {result.method}")
            print(f"[+] Time taken: {result.time_taken:.2f}s")
            print(f"[+] Iterations: {result.iterations}")
        else:
            print("[-] Password not found in dictionary")
    
    print("\n[+] Hash cracker test completed!")

if __name__ == "__main__":
    test_hash_cracker()
