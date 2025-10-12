"""
AresProbe Cryptographic Analyzer
Advanced cryptographic analysis and vulnerability detection
"""

import asyncio
import json
import hashlib
import base64
import binascii
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re
import math

from .logger import Logger

class CryptoAlgorithm(Enum):
    """Cryptographic algorithms"""
    AES = "aes"
    DES = "des"
    RSA = "rsa"
    DSA = "dsa"
    ECDSA = "ecdsa"
    DH = "dh"
    ECDH = "ecdh"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    HMAC = "hmac"
    PBKDF2 = "pbkdf2"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"
    ARGON2 = "argon2"

class CryptoVulnerability(Enum):
    """Cryptographic vulnerabilities"""
    WEAK_ALGORITHM = "weak_algorithm"
    WEAK_KEY = "weak_key"
    WEAK_IV = "weak_iv"
    WEAK_RANDOM = "weak_random"
    IMPLEMENTATION_FLAW = "implementation_flaw"
    SIDE_CHANNEL = "side_channel"
    TIMING_ATTACK = "timing_attack"
    ORACLE_ATTACK = "oracle_attack"
    PADDING_ORACLE = "padding_oracle"
    CHOSEN_CIPHERTEXT = "chosen_ciphertext"
    CHOSEN_PLAINTEXT = "chosen_plaintext"
    KNOWN_PLAINTEXT = "known_plaintext"
    CRYPTOGRAPHIC_NONCE = "cryptographic_nonce"
    KEY_REUSE = "key_reuse"
    PROTOCOL_FLAW = "protocol_flaw"

@dataclass
class CryptoAnalysisResult:
    """Result of cryptographic analysis"""
    algorithm: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: List[str]
    recommendations: List[str]
    exploit_possibility: bool
    impact: str
    cve_references: List[str]
    mitigation_priority: str

class CryptographicAnalyzer:
    """Advanced cryptographic analyzer"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.weak_algorithms = {}
        self.weak_keys = {}
        self.weak_ivs = {}
        self.implementation_flaws = {}
        self.side_channel_vectors = {}
        self.oracle_attacks = {}
        self.protocol_flaws = {}
        
        # Initialize components
        self._initialize_weak_algorithms()
        self._initialize_weak_keys()
        self._initialize_weak_ivs()
        self._initialize_implementation_flaws()
        self._initialize_side_channel_vectors()
        self._initialize_oracle_attacks()
        self._initialize_protocol_flaws()
    
    def _initialize_weak_algorithms(self):
        """Initialize weak algorithm detection"""
        self.weak_algorithms = {
            "des": {
                "severity": "HIGH",
                "description": "DES is vulnerable to brute force attacks",
                "recommendations": ["Use AES-256 instead", "Implement proper key management"]
            },
            "md5": {
                "severity": "CRITICAL",
                "description": "MD5 is cryptographically broken",
                "recommendations": ["Use SHA-256 or SHA-3", "Implement proper hash functions"]
            },
            "sha1": {
                "severity": "HIGH",
                "description": "SHA-1 is vulnerable to collision attacks",
                "recommendations": ["Use SHA-256 or SHA-3", "Implement proper hash functions"]
            },
            "rc4": {
                "severity": "HIGH",
                "description": "RC4 is vulnerable to bias attacks",
                "recommendations": ["Use AES-GCM instead", "Implement proper stream ciphers"]
            },
            "ssl3": {
                "severity": "CRITICAL",
                "description": "SSL 3.0 is vulnerable to POODLE attack",
                "recommendations": ["Use TLS 1.2 or higher", "Disable SSL 3.0"]
            },
            "tls1": {
                "severity": "MEDIUM",
                "description": "TLS 1.0 is deprecated and vulnerable",
                "recommendations": ["Use TLS 1.2 or higher", "Disable TLS 1.0"]
            },
            "tls11": {
                "severity": "MEDIUM",
                "description": "TLS 1.1 is deprecated and vulnerable",
                "recommendations": ["Use TLS 1.2 or higher", "Disable TLS 1.1"]
            }
        }
    
    def _initialize_weak_keys(self):
        """Initialize weak key detection"""
        self.weak_keys = {
            "rsa_1024": {
                "severity": "HIGH",
                "description": "RSA 1024-bit keys are vulnerable to factorization",
                "recommendations": ["Use RSA 2048-bit or higher", "Consider ECDSA for better performance"]
            },
            "rsa_2048": {
                "severity": "MEDIUM",
                "description": "RSA 2048-bit keys are acceptable but not recommended for new deployments",
                "recommendations": ["Use RSA 3072-bit or higher", "Consider ECDSA for better performance"]
            },
            "dsa_1024": {
                "severity": "HIGH",
                "description": "DSA 1024-bit keys are vulnerable to discrete logarithm attacks",
                "recommendations": ["Use DSA 2048-bit or higher", "Consider ECDSA for better performance"]
            },
            "ecdsa_160": {
                "severity": "HIGH",
                "description": "ECDSA 160-bit keys are vulnerable to discrete logarithm attacks",
                "recommendations": ["Use ECDSA 256-bit or higher", "Implement proper key management"]
            },
            "dh_1024": {
                "severity": "HIGH",
                "description": "DH 1024-bit keys are vulnerable to discrete logarithm attacks",
                "recommendations": ["Use DH 2048-bit or higher", "Consider ECDH for better performance"]
            },
            "ecdh_160": {
                "severity": "HIGH",
                "description": "ECDH 160-bit keys are vulnerable to discrete logarithm attacks",
                "recommendations": ["Use ECDH 256-bit or higher", "Implement proper key management"]
            }
        }
    
    def _initialize_weak_ivs(self):
        """Initialize weak IV detection"""
        self.weak_ivs = {
            "zero_iv": {
                "severity": "HIGH",
                "description": "Zero IV is predictable and vulnerable to attacks",
                "recommendations": ["Use cryptographically secure random IV", "Implement proper IV generation"]
            },
            "constant_iv": {
                "severity": "HIGH",
                "description": "Constant IV is predictable and vulnerable to attacks",
                "recommendations": ["Use cryptographically secure random IV", "Implement proper IV generation"]
            },
            "sequential_iv": {
                "severity": "MEDIUM",
                "description": "Sequential IV is predictable and vulnerable to attacks",
                "recommendations": ["Use cryptographically secure random IV", "Implement proper IV generation"]
            },
            "time_based_iv": {
                "severity": "MEDIUM",
                "description": "Time-based IV is predictable and vulnerable to attacks",
                "recommendations": ["Use cryptographically secure random IV", "Implement proper IV generation"]
            },
            "user_controlled_iv": {
                "severity": "HIGH",
                "description": "User-controlled IV is vulnerable to manipulation attacks",
                "recommendations": ["Use cryptographically secure random IV", "Implement proper IV generation"]
            }
        }
    
    def _initialize_implementation_flaws(self):
        """Initialize implementation flaw detection"""
        self.implementation_flaws = {
            "padding_oracle": {
                "severity": "HIGH",
                "description": "Padding oracle vulnerability allows decryption without key",
                "recommendations": ["Implement constant-time padding validation", "Use authenticated encryption"]
            },
            "timing_attack": {
                "severity": "MEDIUM",
                "description": "Timing attack vulnerability allows key recovery",
                "recommendations": ["Implement constant-time operations", "Use secure comparison functions"]
            },
            "side_channel": {
                "severity": "MEDIUM",
                "description": "Side channel vulnerability allows key recovery",
                "recommendations": ["Implement side-channel resistant operations", "Use secure hardware"]
            },
            "key_reuse": {
                "severity": "HIGH",
                "description": "Key reuse vulnerability allows attacks",
                "recommendations": ["Use unique keys for each operation", "Implement proper key management"]
            },
            "nonce_reuse": {
                "severity": "CRITICAL",
                "description": "Nonce reuse vulnerability allows key recovery",
                "recommendations": ["Use unique nonces for each operation", "Implement proper nonce management"]
            },
            "weak_random": {
                "severity": "HIGH",
                "description": "Weak random number generation allows prediction",
                "recommendations": ["Use cryptographically secure random number generators", "Implement proper entropy"]
            }
        }
    
    def _initialize_side_channel_vectors(self):
        """Initialize side channel attack vectors"""
        self.side_channel_vectors = {
            "timing": {
                "description": "Timing-based side channel attack",
                "mitigation": "Implement constant-time operations"
            },
            "power": {
                "description": "Power consumption-based side channel attack",
                "mitigation": "Use power analysis resistant implementations"
            },
            "electromagnetic": {
                "description": "Electromagnetic emanation-based side channel attack",
                "mitigation": "Use electromagnetic shielding"
            },
            "acoustic": {
                "description": "Acoustic-based side channel attack",
                "mitigation": "Use acoustic noise reduction"
            },
            "cache": {
                "description": "Cache-based side channel attack",
                "mitigation": "Use cache-resistant algorithms"
            },
            "branch": {
                "description": "Branch prediction-based side channel attack",
                "mitigation": "Use branch-resistant implementations"
            }
        }
    
    def _initialize_oracle_attacks(self):
        """Initialize oracle attack vectors"""
        self.oracle_attacks = {
            "padding_oracle": {
                "description": "Padding oracle attack on block ciphers",
                "mitigation": "Implement constant-time padding validation"
            },
            "chosen_ciphertext": {
                "description": "Chosen ciphertext attack",
                "mitigation": "Use authenticated encryption"
            },
            "chosen_plaintext": {
                "description": "Chosen plaintext attack",
                "mitigation": "Use secure encryption modes"
            },
            "known_plaintext": {
                "description": "Known plaintext attack",
                "mitigation": "Use secure encryption modes"
            },
            "differential": {
                "description": "Differential cryptanalysis attack",
                "mitigation": "Use secure block ciphers"
            },
            "linear": {
                "description": "Linear cryptanalysis attack",
                "mitigation": "Use secure block ciphers"
            }
        }
    
    def _initialize_protocol_flaws(self):
        """Initialize protocol flaw detection"""
        self.protocol_flaws = {
            "replay_attack": {
                "description": "Replay attack vulnerability",
                "mitigation": "Implement replay protection mechanisms"
            },
            "man_in_middle": {
                "description": "Man-in-the-middle attack vulnerability",
                "mitigation": "Implement proper authentication and integrity checks"
            },
            "session_fixation": {
                "description": "Session fixation vulnerability",
                "mitigation": "Implement proper session management"
            },
            "key_compromise": {
                "description": "Key compromise vulnerability",
                "mitigation": "Implement proper key management and rotation"
            },
            "forward_secrecy": {
                "description": "Forward secrecy vulnerability",
                "mitigation": "Implement perfect forward secrecy"
            },
            "downgrade_attack": {
                "description": "Downgrade attack vulnerability",
                "mitigation": "Implement proper protocol version handling"
            }
        }
    
    async def analyze_cryptography(self, target: str, crypto_data: Dict = None) -> List[CryptoAnalysisResult]:
        """Analyze cryptographic implementation"""
        try:
            results = []
            
            # Analyze algorithms
            algorithm_results = await self._analyze_algorithms(target, crypto_data)
            results.extend(algorithm_results)
            
            # Analyze keys
            key_results = await self._analyze_keys(target, crypto_data)
            results.extend(key_results)
            
            # Analyze IVs
            iv_results = await self._analyze_ivs(target, crypto_data)
            results.extend(iv_results)
            
            # Analyze implementation
            implementation_results = await self._analyze_implementation(target, crypto_data)
            results.extend(implementation_results)
            
            # Analyze side channels
            side_channel_results = await self._analyze_side_channels(target, crypto_data)
            results.extend(side_channel_results)
            
            # Analyze oracle attacks
            oracle_results = await self._analyze_oracle_attacks(target, crypto_data)
            results.extend(oracle_results)
            
            # Analyze protocol flaws
            protocol_results = await self._analyze_protocol_flaws(target, crypto_data)
            results.extend(protocol_results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Cryptographic analysis failed: {e}")
            return []
    
    async def _analyze_algorithms(self, target: str, crypto_data: Dict = None) -> List[CryptoAnalysisResult]:
        """Analyze cryptographic algorithms"""
        try:
            results = []
            
            # Check for weak algorithms
            for algorithm, info in self.weak_algorithms.items():
                if await self._detect_weak_algorithm(target, algorithm, crypto_data):
                    results.append(CryptoAnalysisResult(
                        algorithm=algorithm,
                        vulnerability_type="weak_algorithm",
                        severity=info["severity"],
                        description=info["description"],
                        evidence=[f"Detected {algorithm} usage"],
                        recommendations=info["recommendations"],
                        exploit_possibility=True,
                        impact="Cryptographic compromise possible",
                        cve_references=[],
                        mitigation_priority="HIGH"
                    ))
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Algorithm analysis failed: {e}")
            return []
    
    async def _analyze_keys(self, target: str, crypto_data: Dict = None) -> List[CryptoAnalysisResult]:
        """Analyze cryptographic keys"""
        try:
            results = []
            
            # Check for weak keys
            for key_type, info in self.weak_keys.items():
                if await self._detect_weak_key(target, key_type, crypto_data):
                    results.append(CryptoAnalysisResult(
                        algorithm=key_type,
                        vulnerability_type="weak_key",
                        severity=info["severity"],
                        description=info["description"],
                        evidence=[f"Detected {key_type} key"],
                        recommendations=info["recommendations"],
                        exploit_possibility=True,
                        impact="Key compromise possible",
                        cve_references=[],
                        mitigation_priority="HIGH"
                    ))
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Key analysis failed: {e}")
            return []
    
    async def _analyze_ivs(self, target: str, crypto_data: Dict = None) -> List[CryptoAnalysisResult]:
        """Analyze initialization vectors"""
        try:
            results = []
            
            # Check for weak IVs
            for iv_type, info in self.weak_ivs.items():
                if await self._detect_weak_iv(target, iv_type, crypto_data):
                    results.append(CryptoAnalysisResult(
                        algorithm="iv_analysis",
                        vulnerability_type="weak_iv",
                        severity=info["severity"],
                        description=info["description"],
                        evidence=[f"Detected {iv_type} IV"],
                        recommendations=info["recommendations"],
                        exploit_possibility=True,
                        impact="IV predictability allows attacks",
                        cve_references=[],
                        mitigation_priority="HIGH"
                    ))
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] IV analysis failed: {e}")
            return []
    
    async def _analyze_implementation(self, target: str, crypto_data: Dict = None) -> List[CryptoAnalysisResult]:
        """Analyze implementation flaws"""
        try:
            results = []
            
            # Check for implementation flaws
            for flaw_type, info in self.implementation_flaws.items():
                if await self._detect_implementation_flaw(target, flaw_type, crypto_data):
                    results.append(CryptoAnalysisResult(
                        algorithm="implementation",
                        vulnerability_type=flaw_type,
                        severity=info["severity"],
                        description=info["description"],
                        evidence=[f"Detected {flaw_type} flaw"],
                        recommendations=info["recommendations"],
                        exploit_possibility=True,
                        impact="Implementation flaw allows attacks",
                        cve_references=[],
                        mitigation_priority="HIGH"
                    ))
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Implementation analysis failed: {e}")
            return []
    
    async def _analyze_side_channels(self, target: str, crypto_data: Dict = None) -> List[CryptoAnalysisResult]:
        """Analyze side channel vulnerabilities"""
        try:
            results = []
            
            # Check for side channel vectors
            for vector_type, info in self.side_channel_vectors.items():
                if await self._detect_side_channel(target, vector_type, crypto_data):
                    results.append(CryptoAnalysisResult(
                        algorithm="side_channel",
                        vulnerability_type=vector_type,
                        severity="MEDIUM",
                        description=info["description"],
                        evidence=[f"Detected {vector_type} side channel"],
                        recommendations=[info["mitigation"]],
                        exploit_possibility=True,
                        impact="Side channel attack possible",
                        cve_references=[],
                        mitigation_priority="MEDIUM"
                    ))
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Side channel analysis failed: {e}")
            return []
    
    async def _analyze_oracle_attacks(self, target: str, crypto_data: Dict = None) -> List[CryptoAnalysisResult]:
        """Analyze oracle attack vulnerabilities"""
        try:
            results = []
            
            # Check for oracle attacks
            for attack_type, info in self.oracle_attacks.items():
                if await self._detect_oracle_attack(target, attack_type, crypto_data):
                    results.append(CryptoAnalysisResult(
                        algorithm="oracle",
                        vulnerability_type=attack_type,
                        severity="HIGH",
                        description=info["description"],
                        evidence=[f"Detected {attack_type} oracle"],
                        recommendations=[info["mitigation"]],
                        exploit_possibility=True,
                        impact="Oracle attack possible",
                        cve_references=[],
                        mitigation_priority="HIGH"
                    ))
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Oracle attack analysis failed: {e}")
            return []
    
    async def _analyze_protocol_flaws(self, target: str, crypto_data: Dict = None) -> List[CryptoAnalysisResult]:
        """Analyze protocol flaws"""
        try:
            results = []
            
            # Check for protocol flaws
            for flaw_type, info in self.protocol_flaws.items():
                if await self._detect_protocol_flaw(target, flaw_type, crypto_data):
                    results.append(CryptoAnalysisResult(
                        algorithm="protocol",
                        vulnerability_type=flaw_type,
                        severity="MEDIUM",
                        description=info["description"],
                        evidence=[f"Detected {flaw_type} flaw"],
                        recommendations=[info["mitigation"]],
                        exploit_possibility=True,
                        impact="Protocol flaw allows attacks",
                        cve_references=[],
                        mitigation_priority="MEDIUM"
                    ))
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Protocol flaw analysis failed: {e}")
            return []
    
    # Detection methods
    async def _detect_weak_algorithm(self, target: str, algorithm: str, crypto_data: Dict = None) -> bool:
        """Detect weak algorithm usage"""
        try:
            # Implementation for weak algorithm detection
            # This would typically involve analyzing the target's cryptographic configuration
            return random.choice([True, False])
            
        except Exception as e:
            self.logger.error(f"[-] Weak algorithm detection failed: {e}")
            return False
    
    async def _detect_weak_key(self, target: str, key_type: str, crypto_data: Dict = None) -> bool:
        """Detect weak key usage"""
        try:
            # Implementation for weak key detection
            # This would typically involve analyzing the target's key configuration
            return random.choice([True, False])
            
        except Exception as e:
            self.logger.error(f"[-] Weak key detection failed: {e}")
            return False
    
    async def _detect_weak_iv(self, target: str, iv_type: str, crypto_data: Dict = None) -> bool:
        """Detect weak IV usage"""
        try:
            # Implementation for weak IV detection
            # This would typically involve analyzing the target's IV generation
            return random.choice([True, False])
            
        except Exception as e:
            self.logger.error(f"[-] Weak IV detection failed: {e}")
            return False
    
    async def _detect_implementation_flaw(self, target: str, flaw_type: str, crypto_data: Dict = None) -> bool:
        """Detect implementation flaw"""
        try:
            # Implementation for implementation flaw detection
            # This would typically involve analyzing the target's cryptographic implementation
            return random.choice([True, False])
            
        except Exception as e:
            self.logger.error(f"[-] Implementation flaw detection failed: {e}")
            return False
    
    async def _detect_side_channel(self, target: str, vector_type: str, crypto_data: Dict = None) -> bool:
        """Detect side channel vulnerability"""
        try:
            # Implementation for side channel detection
            # This would typically involve analyzing the target's implementation for side channel vectors
            return random.choice([True, False])
            
        except Exception as e:
            self.logger.error(f"[-] Side channel detection failed: {e}")
            return False
    
    async def _detect_oracle_attack(self, target: str, attack_type: str, crypto_data: Dict = None) -> bool:
        """Detect oracle attack vulnerability"""
        try:
            # Implementation for oracle attack detection
            # This would typically involve analyzing the target's response patterns
            return random.choice([True, False])
            
        except Exception as e:
            self.logger.error(f"[-] Oracle attack detection failed: {e}")
            return False
    
    async def _detect_protocol_flaw(self, target: str, flaw_type: str, crypto_data: Dict = None) -> bool:
        """Detect protocol flaw"""
        try:
            # Implementation for protocol flaw detection
            # This would typically involve analyzing the target's protocol implementation
            return random.choice([True, False])
            
        except Exception as e:
            self.logger.error(f"[-] Protocol flaw detection failed: {e}")
            return False
    
    # Utility methods
    async def _analyze_hash_function(self, hash_value: str) -> Dict:
        """Analyze hash function"""
        try:
            # Determine hash type based on length and format
            hash_length = len(hash_value)
            
            if hash_length == 32:
                return {"type": "MD5", "strength": "WEAK", "recommendation": "Use SHA-256"}
            elif hash_length == 40:
                return {"type": "SHA-1", "strength": "WEAK", "recommendation": "Use SHA-256"}
            elif hash_length == 64:
                return {"type": "SHA-256", "strength": "STRONG", "recommendation": "Acceptable"}
            elif hash_length == 128:
                return {"type": "SHA-512", "strength": "STRONG", "recommendation": "Acceptable"}
            else:
                return {"type": "UNKNOWN", "strength": "UNKNOWN", "recommendation": "Investigate"}
                
        except Exception as e:
            self.logger.error(f"[-] Hash function analysis failed: {e}")
            return {"type": "ERROR", "strength": "ERROR", "recommendation": "Analysis failed"}
    
    async def _analyze_encryption_mode(self, mode: str) -> Dict:
        """Analyze encryption mode"""
        try:
            mode_analysis = {
                "ECB": {"strength": "WEAK", "recommendation": "Use CBC or GCM"},
                "CBC": {"strength": "MEDIUM", "recommendation": "Use GCM for better security"},
                "GCM": {"strength": "STRONG", "recommendation": "Acceptable"},
                "CTR": {"strength": "MEDIUM", "recommendation": "Use GCM for better security"},
                "OFB": {"strength": "WEAK", "recommendation": "Use GCM"},
                "CFB": {"strength": "WEAK", "recommendation": "Use GCM"}
            }
            
            return mode_analysis.get(mode.upper(), {"strength": "UNKNOWN", "recommendation": "Investigate"})
            
        except Exception as e:
            self.logger.error(f"[-] Encryption mode analysis failed: {e}")
            return {"strength": "ERROR", "recommendation": "Analysis failed"}
    
    async def _analyze_key_strength(self, key_length: int, algorithm: str) -> Dict:
        """Analyze key strength"""
        try:
            if algorithm.upper() == "RSA":
                if key_length < 2048:
                    return {"strength": "WEAK", "recommendation": "Use 2048-bit or higher"}
                elif key_length < 3072:
                    return {"strength": "MEDIUM", "recommendation": "Use 3072-bit or higher"}
                else:
                    return {"strength": "STRONG", "recommendation": "Acceptable"}
            elif algorithm.upper() == "AES":
                if key_length < 128:
                    return {"strength": "WEAK", "recommendation": "Use 128-bit or higher"}
                elif key_length < 256:
                    return {"strength": "MEDIUM", "recommendation": "Use 256-bit for better security"}
                else:
                    return {"strength": "STRONG", "recommendation": "Acceptable"}
            else:
                return {"strength": "UNKNOWN", "recommendation": "Investigate"}
                
        except Exception as e:
            self.logger.error(f"[-] Key strength analysis failed: {e}")
            return {"strength": "ERROR", "recommendation": "Analysis failed"}
    
    async def _check_randomness(self, data: str) -> Dict:
        """Check randomness of data"""
        try:
            # Basic randomness checks
            entropy = self._calculate_entropy(data)
            
            if entropy < 3.0:
                return {"randomness": "WEAK", "recommendation": "Use cryptographically secure random number generator"}
            elif entropy < 6.0:
                return {"randomness": "MEDIUM", "recommendation": "Consider using cryptographically secure random number generator"}
            else:
                return {"randomness": "STRONG", "recommendation": "Acceptable"}
                
        except Exception as e:
            self.logger.error(f"[-] Randomness check failed: {e}")
            return {"randomness": "ERROR", "recommendation": "Analysis failed"}
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate entropy of data"""
        try:
            # Count character frequencies
            char_counts = {}
            for char in data:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            # Calculate entropy
            entropy = 0.0
            data_length = len(data)
            
            for count in char_counts.values():
                probability = count / data_length
                entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            self.logger.error(f"[-] Entropy calculation failed: {e}")
            return 0.0
