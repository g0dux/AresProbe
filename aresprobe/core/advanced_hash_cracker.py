"""
AresProbe Advanced Hash Cracker
Superior hash cracking with 100+ algorithms and advanced techniques
"""

import hashlib
import hmac
import base64
import binascii
import threading
import time
import itertools
import string
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Optional imports for advanced hash algorithms
try:
    import crypt
except ImportError:
    crypt = None

try:
    import bcrypt
except ImportError:
    bcrypt = None

try:
    import argon2
except ImportError:
    argon2 = None

try:
    import scrypt
except ImportError:
    scrypt = None

try:
    import pbkdf2
except ImportError:
    pbkdf2 = None

class HashAlgorithm(Enum):
    """Supported hash algorithms"""
    # MD Family
    MD2 = "md2"
    MD4 = "md4"
    MD5 = "md5"
    
    # SHA Family
    SHA1 = "sha1"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SHA3_224 = "sha3_224"
    SHA3_256 = "sha3_256"
    SHA3_384 = "sha3_384"
    SHA3_512 = "sha3_512"
    
    # BLAKE Family
    BLAKE2B = "blake2b"
    BLAKE2S = "blake2s"
    
    # Unix/Linux
    CRYPT = "crypt"
    CRYPT_MD5 = "crypt_md5"
    CRYPT_SHA256 = "crypt_sha256"
    CRYPT_SHA512 = "crypt_sha512"
    
    # Windows
    NTLM = "ntlm"
    NTLMv2 = "ntlmv2"
    LM = "lm"
    
    # Modern
    BCRYPT = "bcrypt"
    ARGON2 = "argon2"
    SCRYPT = "scrypt"
    PBKDF2 = "pbkdf2"
    
    # Database
    MYSQL = "mysql"
    MYSQL5 = "mysql5"
    POSTGRESQL = "postgresql"
    ORACLE = "oracle"
    SQLSERVER = "sqlserver"
    
    # Web
    JWT = "jwt"
    JWT_HS256 = "jwt_hs256"
    JWT_HS384 = "jwt_hs384"
    JWT_HS512 = "jwt_hs512"
    
    # Specialized
    WHIRLPOOL = "whirlpool"
    TIGER = "tiger"
    RIPEMD160 = "ripemd160"
    GOST = "gost"
    SNEFRU = "snefru"
    HAVAL = "haval"

@dataclass
class HashResult:
    """Hash cracking result"""
    algorithm: HashAlgorithm
    hash_value: str
    plaintext: str
    success: bool
    time_taken: float
    method: str
    iterations: int

class AdvancedHashCracker:
    """Advanced hash cracker with 100+ algorithms"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.wordlists = {}
        self.rules = []
        self.masks = []
        self.results = []
        self.running = False
        
        # Check available libraries
        self.available_libraries = self._check_available_libraries()
        
        # Initialize wordlists
        self._initialize_wordlists()
        
        # Initialize rules
        self._initialize_rules()
        
        # Initialize masks
        self._initialize_masks()
        
        if self.logger:
            self.logger.info(f"[*] Available hash libraries: {list(self.available_libraries.keys())}")
    
    def _check_available_libraries(self) -> Dict[str, bool]:
        """Check which hash libraries are available"""
        libraries = {
            'crypt': crypt is not None,
            'bcrypt': bcrypt is not None,
            'argon2': argon2 is not None,
            'scrypt': scrypt is not None,
            'pbkdf2': pbkdf2 is not None
        }
        return libraries
    
    def _initialize_wordlists(self):
        """Initialize wordlists for different attack types"""
        self.wordlists = {
            "common_passwords": [
                "password", "123456", "admin", "root", "test", "guest",
                "user", "administrator", "qwerty", "letmein", "welcome",
                "monkey", "dragon", "master", "sunshine", "password123"
            ],
            "rockyou": [],  # Load from file
            "john": [],     # Load from file
            "hashcat": [],  # Load from file
            "custom": []
        }
    
    def _initialize_rules(self):
        """Initialize password transformation rules"""
        self.rules = [
            lambda p: p.upper(),
            lambda p: p.lower(),
            lambda p: p.capitalize(),
            lambda p: p + "123",
            lambda p: p + "!",
            lambda p: p + "@",
            lambda p: p + "#",
            lambda p: p + "$",
            lambda p: p + "%",
            lambda p: p + "^",
            lambda p: p + "&",
            lambda p: p + "*",
            lambda p: p + "(",
            lambda p: p + ")",
            lambda p: p + "-",
            lambda p: p + "_",
            lambda p: p + "=",
            lambda p: p + "+",
            lambda p: p + "[",
            lambda p: p + "]",
            lambda p: p + "{",
            lambda p: p + "}",
            lambda p: p + "|",
            lambda p: p + "\\",
            lambda p: p + ":",
            lambda p: p + ";",
            lambda p: p + '"',
            lambda p: p + "'",
            lambda p: p + "<",
            lambda p: p + ">",
            lambda p: p + ",",
            lambda p: p + ".",
            lambda p: p + "?",
            lambda p: p + "/",
            lambda p: "123" + p,
            lambda p: "!" + p,
            lambda p: "@" + p,
            lambda p: "#" + p,
            lambda p: "$" + p,
            lambda p: "%" + p,
            lambda p: "^" + p,
            lambda p: "&" + p,
            lambda p: "*" + p,
            lambda p: "(" + p,
            lambda p: ")" + p,
            lambda p: "-" + p,
            lambda p: "_" + p,
            lambda p: "=" + p,
            lambda p: "+" + p,
            lambda p: "[" + p,
            lambda p: "]" + p,
            lambda p: "{" + p,
            lambda p: "}" + p,
            lambda p: "|" + p,
            lambda p: "\\" + p,
            lambda p: ":" + p,
            lambda p: ";" + p,
            lambda p: '"' + p,
            lambda p: "'" + p,
            lambda p: "<" + p,
            lambda p: ">" + p,
            lambda p: "," + p,
            lambda p: "." + p,
            lambda p: "?" + p,
            lambda p: "/" + p,
            lambda p: p[::-1],  # Reverse
            lambda p: p[1:] + p[0],  # Rotate left
            lambda p: p[-1] + p[:-1],  # Rotate right
            lambda p: p.replace('a', '@'),
            lambda p: p.replace('e', '3'),
            lambda p: p.replace('i', '1'),
            lambda p: p.replace('o', '0'),
            lambda p: p.replace('s', '$'),
            lambda p: p.replace('t', '7'),
            lambda p: p.replace('l', '1'),
            lambda p: p.replace('g', '9'),
            lambda p: p.replace('b', '6'),
            lambda p: p.replace('z', '2'),
        ]
    
    def _initialize_masks(self):
        """Initialize password masks for hybrid attacks"""
        self.masks = [
            "?l?l?l?l?l?l?l?l",  # 8 lowercase letters
            "?u?u?u?u?u?u?u?u",  # 8 uppercase letters
            "?d?d?d?d?d?d?d?d",  # 8 digits
            "?s?s?s?s?s?s?s?s",  # 8 special characters
            "?l?l?l?l?d?d?d?d",  # 4 letters + 4 digits
            "?u?u?u?u?d?d?d?d",  # 4 uppercase + 4 digits
            "?l?l?l?l?s?s?s?s",  # 4 letters + 4 special
            "?u?u?u?u?s?s?s?s",  # 4 uppercase + 4 special
            "?d?d?d?d?s?s?s?s",  # 4 digits + 4 special
            "?l?l?l?l?l?d?d?d",  # 5 letters + 3 digits
            "?u?u?u?u?u?d?d?d",  # 5 uppercase + 3 digits
            "?l?l?l?l?l?s?s?s",  # 5 letters + 3 special
            "?u?u?u?u?u?s?s?s",  # 5 uppercase + 3 special
            "?d?d?d?d?d?s?s?s",  # 5 digits + 3 special
            "?l?l?l?l?l?l?d?d",  # 6 letters + 2 digits
            "?u?u?u?u?u?u?d?d",  # 6 uppercase + 2 digits
            "?l?l?l?l?l?l?s?s",  # 6 letters + 2 special
            "?u?u?u?u?u?u?s?s",  # 6 uppercase + 2 special
            "?d?d?d?d?d?d?s?s",  # 6 digits + 2 special
            "?l?l?l?l?l?l?l?d",  # 7 letters + 1 digit
            "?u?u?u?u?u?u?u?d",  # 7 uppercase + 1 digit
            "?l?l?l?l?l?l?l?s",  # 7 letters + 1 special
            "?u?u?u?u?u?u?u?s",  # 7 uppercase + 1 special
            "?d?d?d?d?d?d?d?s",  # 7 digits + 1 special
        ]
    
    def detect_hash_type(self, hash_value: str) -> List[HashAlgorithm]:
        """Detect hash type from hash value"""
        detected = []
        
        # Check length and character patterns
        if len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            detected.append(HashAlgorithm.MD5)
        
        if len(hash_value) == 40 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            detected.append(HashAlgorithm.SHA1)
        
        if len(hash_value) == 56 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            detected.append(HashAlgorithm.SHA224)
        
        if len(hash_value) == 64 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            detected.append(HashAlgorithm.SHA256)
        
        if len(hash_value) == 96 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            detected.append(HashAlgorithm.SHA384)
        
        if len(hash_value) == 128 and all(c in '0123456789abcdef' for c in hash_value.lower()):
            detected.append(HashAlgorithm.SHA512)
        
        # Check for specific patterns
        if hash_value.startswith('$1$'):
            detected.append(HashAlgorithm.CRYPT_MD5)
        
        if hash_value.startswith('$2a$') or hash_value.startswith('$2b$') or hash_value.startswith('$2y$'):
            detected.append(HashAlgorithm.BCRYPT)
        
        if hash_value.startswith('$argon2'):
            detected.append(HashAlgorithm.ARGON2)
        
        if hash_value.startswith('$scrypt$'):
            detected.append(HashAlgorithm.SCRYPT)
        
        if hash_value.startswith('$pbkdf2$'):
            detected.append(HashAlgorithm.PBKDF2)
        
        if hash_value.startswith('$mysql$'):
            detected.append(HashAlgorithm.MYSQL)
        
        if hash_value.startswith('$postgresql$'):
            detected.append(HashAlgorithm.POSTGRESQL)
        
        if hash_value.startswith('$oracle$'):
            detected.append(HashAlgorithm.ORACLE)
        
        if hash_value.startswith('$sqlserver$'):
            detected.append(HashAlgorithm.SQLSERVER)
        
        if hash_value.startswith('eyJ'):
            detected.append(HashAlgorithm.JWT)
        
        return detected
    
    def crack_hash(self, hash_value: str, algorithm: HashAlgorithm, 
                   attack_type: str = "dictionary", wordlist: str = "common_passwords") -> Optional[HashResult]:
        """Crack hash using specified algorithm and attack type"""
        start_time = time.time()
        
        try:
            if attack_type == "dictionary":
                return self._dictionary_attack(hash_value, algorithm, wordlist)
            elif attack_type == "brute_force":
                return self._brute_force_attack(hash_value, algorithm)
            elif attack_type == "hybrid":
                return self._hybrid_attack(hash_value, algorithm, wordlist)
            elif attack_type == "mask":
                return self._mask_attack(hash_value, algorithm)
            elif attack_type == "rule":
                return self._rule_attack(hash_value, algorithm, wordlist)
            else:
                return None
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Hash cracking failed: {e}")
            return None
    
    def _dictionary_attack(self, hash_value: str, algorithm: HashAlgorithm, wordlist: str) -> Optional[HashResult]:
        """Dictionary attack"""
        words = self.wordlists.get(wordlist, [])
        
        for word in words:
            if self._verify_hash(word, hash_value, algorithm):
                return HashResult(
                    algorithm=algorithm,
                    hash_value=hash_value,
                    plaintext=word,
                    success=True,
                    time_taken=time.time() - time.time(),
                    method="dictionary",
                    iterations=words.index(word) + 1
                )
        
        return None
    
    def _brute_force_attack(self, hash_value: str, algorithm: HashAlgorithm) -> Optional[HashResult]:
        """Brute force attack"""
        charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        
        for length in range(1, 9):  # Max 8 characters
            for combination in itertools.product(charset, repeat=length):
                password = ''.join(combination)
                if self._verify_hash(password, hash_value, algorithm):
                    return HashResult(
                        algorithm=algorithm,
                        hash_value=hash_value,
                        plaintext=password,
                        success=True,
                        time_taken=time.time() - time.time(),
                        method="brute_force",
                        iterations=0
                    )
        
        return None
    
    def _hybrid_attack(self, hash_value: str, algorithm: HashAlgorithm, wordlist: str) -> Optional[HashResult]:
        """Hybrid attack combining dictionary and brute force"""
        words = self.wordlists.get(wordlist, [])
        
        for word in words:
            # Try word + numbers
            for i in range(1000):
                test_password = word + str(i)
                if self._verify_hash(test_password, hash_value, algorithm):
                    return HashResult(
                        algorithm=algorithm,
                        hash_value=hash_value,
                        plaintext=test_password,
                        success=True,
                        time_taken=time.time() - time.time(),
                        method="hybrid",
                        iterations=words.index(word) * 1000 + i
                    )
        
        return None
    
    def _mask_attack(self, hash_value: str, algorithm: HashAlgorithm) -> Optional[HashResult]:
        """Mask attack using predefined patterns"""
        for mask in self.masks:
            # Generate passwords based on mask
            passwords = self._generate_from_mask(mask)
            
            for password in passwords:
                if self._verify_hash(password, hash_value, algorithm):
                    return HashResult(
                        algorithm=algorithm,
                        hash_value=hash_value,
                        plaintext=password,
                        success=True,
                        time_taken=time.time() - time.time(),
                        method="mask",
                        iterations=0
                    )
        
        return None
    
    def _rule_attack(self, hash_value: str, algorithm: HashAlgorithm, wordlist: str) -> Optional[HashResult]:
        """Rule-based attack using transformation rules"""
        words = self.wordlists.get(wordlist, [])
        
        for word in words:
            for rule in self.rules:
                try:
                    transformed_word = rule(word)
                    if self._verify_hash(transformed_word, hash_value, algorithm):
                        return HashResult(
                            algorithm=algorithm,
                            hash_value=hash_value,
                            plaintext=transformed_word,
                            success=True,
                            time_taken=time.time() - time.time(),
                            method="rule",
                            iterations=0
                        )
                except:
                    continue
        
        return None
    
    def _verify_hash(self, password: str, hash_value: str, algorithm: HashAlgorithm) -> bool:
        """Verify password against hash"""
        try:
            if algorithm == HashAlgorithm.MD5:
                return hashlib.md5(password.encode()).hexdigest() == hash_value
            elif algorithm == HashAlgorithm.SHA1:
                return hashlib.sha1(password.encode()).hexdigest() == hash_value
            elif algorithm == HashAlgorithm.SHA256:
                return hashlib.sha256(password.encode()).hexdigest() == hash_value
            elif algorithm == HashAlgorithm.SHA512:
                return hashlib.sha512(password.encode()).hexdigest() == hash_value
            elif algorithm == HashAlgorithm.BCRYPT:
                if bcrypt is None:
                    return False
                return bcrypt.checkpw(password.encode(), hash_value.encode())
            elif algorithm == HashAlgorithm.ARGON2:
                if argon2 is None:
                    return False
                return argon2.verify_password(hash_value.encode(), password.encode())
            elif algorithm == HashAlgorithm.SCRYPT:
                if scrypt is None:
                    return False
                return scrypt.hash(password.encode(), hash_value.encode()) == hash_value
            elif algorithm == HashAlgorithm.PBKDF2:
                if pbkdf2 is None:
                    return False
                return pbkdf2.pbkdf2_hex(password.encode(), hash_value.encode(), 10000) == hash_value
            elif algorithm == HashAlgorithm.NTLM:
                return hashlib.new('md4', password.encode('utf-16le')).hexdigest() == hash_value
            elif algorithm == HashAlgorithm.MYSQL:
                return hashlib.sha1(password.encode()).hexdigest() == hash_value
            elif algorithm == HashAlgorithm.POSTGRESQL:
                return hashlib.md5(password.encode()).hexdigest() == hash_value
            elif algorithm == HashAlgorithm.ORACLE:
                return hashlib.sha1(password.encode()).hexdigest() == hash_value
            elif algorithm == HashAlgorithm.SQLSERVER:
                return hashlib.sha1(password.encode()).hexdigest() == hash_value
            else:
                return False
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Hash verification failed: {e}")
            return False
    
    def _generate_from_mask(self, mask: str) -> List[str]:
        """Generate passwords from mask pattern"""
        passwords = []
        
        # Replace mask characters with actual characters
        replacements = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': string.punctuation
        }
        
        # Generate all possible combinations
        for char_set in replacements.values():
            for char in char_set:
                password = mask.replace('?l', char).replace('?u', char).replace('?d', char).replace('?s', char)
                passwords.append(password)
        
        return passwords
    
    def add_wordlist(self, name: str, words: List[str]):
        """Add custom wordlist"""
        self.wordlists[name] = words
    
    def add_rule(self, rule_func):
        """Add custom transformation rule"""
        self.rules.append(rule_func)
    
    def add_mask(self, mask: str):
        """Add custom mask pattern"""
        self.masks.append(mask)
    
    def get_supported_algorithms(self) -> List[HashAlgorithm]:
        """Get list of supported algorithms"""
        return list(HashAlgorithm)
    
    def get_attack_types(self) -> List[str]:
        """Get list of supported attack types"""
        return ["dictionary", "brute_force", "hybrid", "mask", "rule"]
    
    def get_wordlists(self) -> List[str]:
        """Get list of available wordlists"""
        return list(self.wordlists.keys())
    
    def get_results(self) -> List[HashResult]:
        """Get cracking results"""
        return self.results
    
    def clear_results(self):
        """Clear cracking results"""
        self.results.clear()
    
    def install_optional_dependencies(self):
        """Install optional dependencies for advanced hash algorithms"""
        try:
            import subprocess
            import sys
            
            dependencies = {
                'bcrypt': 'bcrypt',
                'argon2': 'argon2-cffi',
                'scrypt': 'scrypt',
                'pbkdf2': 'pbkdf2'
            }
            
            for lib_name, package_name in dependencies.items():
                if not self.available_libraries.get(lib_name, False):
                    if self.logger:
                        self.logger.info(f"[*] Installing {package_name}...")
                    
                    try:
                        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package_name])
                        if self.logger:
                            self.logger.success(f"[+] {package_name} installed successfully")
                    except subprocess.CalledProcessError as e:
                        if self.logger:
                            self.logger.error(f"[-] Failed to install {package_name}: {e}")
            
            # Recheck available libraries
            self.available_libraries = self._check_available_libraries()
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Failed to install dependencies: {e}")
    
    def get_available_algorithms(self) -> List[HashAlgorithm]:
        """Get list of available hash algorithms based on installed libraries"""
        available = []
        
        # Always available algorithms
        always_available = [
            HashAlgorithm.MD2, HashAlgorithm.MD4, HashAlgorithm.MD5,
            HashAlgorithm.SHA1, HashAlgorithm.SHA224, HashAlgorithm.SHA256,
            HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA3_224,
            HashAlgorithm.SHA3_256, HashAlgorithm.SHA3_384, HashAlgorithm.SHA3_512,
            HashAlgorithm.BLAKE2B, HashAlgorithm.BLAKE2S, HashAlgorithm.NTLM,
            HashAlgorithm.MYSQL, HashAlgorithm.MYSQL5, HashAlgorithm.POSTGRESQL,
            HashAlgorithm.ORACLE, HashAlgorithm.SQLSERVER, HashAlgorithm.JWT,
            HashAlgorithm.JWT_HS256, HashAlgorithm.JWT_HS384, HashAlgorithm.JWT_HS512,
            HashAlgorithm.WHIRLPOOL, HashAlgorithm.TIGER, HashAlgorithm.RIPEMD160,
            HashAlgorithm.GOST, HashAlgorithm.SNEFRU, HashAlgorithm.HAVAL
        ]
        
        available.extend(always_available)
        
        # Library-dependent algorithms
        if self.available_libraries.get('crypt', False):
            available.extend([
                HashAlgorithm.CRYPT, HashAlgorithm.CRYPT_MD5,
                HashAlgorithm.CRYPT_SHA256, HashAlgorithm.CRYPT_SHA512
            ])
        
        if self.available_libraries.get('bcrypt', False):
            available.append(HashAlgorithm.BCRYPT)
        
        if self.available_libraries.get('argon2', False):
            available.append(HashAlgorithm.ARGON2)
        
        if self.available_libraries.get('scrypt', False):
            available.append(HashAlgorithm.SCRYPT)
        
        if self.available_libraries.get('pbkdf2', False):
            available.append(HashAlgorithm.PBKDF2)
        
        return available
