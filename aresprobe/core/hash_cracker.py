"""
AresProbe Hash Cracking System
Automatic hash cracking like SQLMap
"""

import hashlib
import itertools
import string
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from .logger import Logger


class HashType(Enum):
    """Supported hash types"""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    NTLM = "ntlm"
    LM = "lm"
    APACHE = "apache"
    PHPBB = "phpbb"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"


@dataclass
class CrackResult:
    """Hash cracking result"""
    hash_value: str
    hash_type: HashType
    cracked: bool
    plaintext: Optional[str]
    method: str
    time_taken: float
    attempts: int


class HashCracker:
    """
    Advanced hash cracking system
    Supports multiple hash types and cracking methods
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.wordlists = {
            'common_passwords': self._load_common_passwords(),
            'rockyou': self._load_rockyou_wordlist(),
            'names': self._load_names_wordlist(),
            'dates': self._load_dates_wordlist()
        }
        self.cracked_hashes = {}
        self.cracking_stats = {
            'total_hashes': 0,
            'cracked_hashes': 0,
            'failed_hashes': 0,
            'total_time': 0
        }
    
    def crack_hash(self, hash_value: str, hash_type: Optional[HashType] = None) -> CrackResult:
        """Crack a single hash"""
        try:
            self.logger.info(f"[*] Attempting to crack hash: {hash_value[:20]}...")
            
            # Auto-detect hash type if not provided
            if not hash_type:
                hash_type = self._detect_hash_type(hash_value)
            
            if not hash_type:
                return CrackResult(hash_value, None, False, None, "unknown", 0, 0)
            
            start_time = time.time()
            result = self._crack_with_methods(hash_value, hash_type)
            time_taken = time.time() - start_time
            
            result.time_taken = time_taken
            self.cracked_hashes[hash_value] = result
            
            if result.cracked:
                self.logger.success(f"[+] Hash cracked: {result.plaintext}")
                self.cracking_stats['cracked_hashes'] += 1
            else:
                self.logger.info(f"[-] Hash not cracked: {hash_value[:20]}...")
                self.cracking_stats['failed_hashes'] += 1
            
            self.cracking_stats['total_hashes'] += 1
            self.cracking_stats['total_time'] += time_taken
            
            return result
            
        except Exception as e:
            self.logger.error(f"[-] Hash cracking failed: {e}")
            return CrackResult(hash_value, hash_type, False, None, "error", 0, 0)
    
    def crack_multiple_hashes(self, hashes: List[str], hash_type: Optional[HashType] = None) -> List[CrackResult]:
        """Crack multiple hashes in parallel"""
        results = []
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self.crack_hash, hash_val, hash_type): hash_val for hash_val in hashes}
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        return results
    
    def _detect_hash_type(self, hash_value: str) -> Optional[HashType]:
        """Auto-detect hash type based on length and format"""
        hash_len = len(hash_value)
        
        # Remove common prefixes
        clean_hash = hash_value.replace('$', '').replace('*', '')
        
        if hash_len == 32 and all(c in string.hexdigits for c in clean_hash):
            return HashType.MD5
        elif hash_len == 40 and all(c in string.hexdigits for c in clean_hash):
            return HashType.SHA1
        elif hash_len == 64 and all(c in string.hexdigits for c in clean_hash):
            return HashType.SHA256
        elif hash_len == 128 and all(c in string.hexdigits for c in clean_hash):
            return HashType.SHA512
        elif hash_len == 32 and clean_hash.startswith('*'):
            return HashType.MYSQL
        elif hash_len == 34 and clean_hash.startswith('md5'):
            return HashType.POSTGRESQL
        elif hash_len == 32 and clean_hash.isalnum():
            return HashType.NTLM
        elif hash_len == 16 and clean_hash.isalnum():
            return HashType.LM
        elif clean_hash.startswith('$2a$') or clean_hash.startswith('$2b$'):
            return HashType.APACHE
        elif clean_hash.startswith('$P$'):
            return HashType.PHPBB
        elif clean_hash.startswith('$S$'):
            return HashType.DRUPAL
        
        return None
    
    def _crack_with_methods(self, hash_value: str, hash_type: HashType) -> CrackResult:
        """Try different cracking methods"""
        methods = [
            self._dictionary_attack,
            self._brute_force_attack,
            self._hybrid_attack,
            self._mask_attack
        ]
        
        for method in methods:
            try:
                result = method(hash_value, hash_type)
                if result.cracked:
                    return result
            except Exception as e:
                self.logger.debug(f"[-] Method {method.__name__} failed: {e}")
                continue
        
        return CrackResult(hash_value, hash_type, False, None, "all_methods_failed", 0, 0)
    
    def _dictionary_attack(self, hash_value: str, hash_type: HashType) -> CrackResult:
        """Dictionary attack using wordlists"""
        attempts = 0
        
        for wordlist_name, wordlist in self.wordlists.items():
            for word in wordlist:
                attempts += 1
                if self._verify_hash(word, hash_value, hash_type):
                    return CrackResult(hash_value, hash_type, True, word, f"dictionary_{wordlist_name}", 0, attempts)
        
        return CrackResult(hash_value, hash_type, False, None, "dictionary", 0, attempts)
    
    def _brute_force_attack(self, hash_value: str, hash_type: HashType) -> CrackResult:
        """Brute force attack with character sets"""
        attempts = 0
        max_length = 6  # Limit for performance
        
        # Character sets
        char_sets = [
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            string.ascii_letters + string.digits,
            string.ascii_letters + string.digits + "!@#$%^&*"
        ]
        
        for length in range(1, max_length + 1):
            for char_set in char_sets:
                for combination in itertools.product(char_set, repeat=length):
                    attempts += 1
                    word = ''.join(combination)
                    
                    if self._verify_hash(word, hash_value, hash_type):
                        return CrackResult(hash_value, hash_type, True, word, "brute_force", 0, attempts)
        
        return CrackResult(hash_value, hash_type, False, None, "brute_force", 0, attempts)
    
    def _hybrid_attack(self, hash_value: str, hash_type: HashType) -> CrackResult:
        """Hybrid attack combining dictionary and brute force"""
        attempts = 0
        
        # Common suffixes and prefixes
        suffixes = ['123', '!', '@', '#', '$', '%', '^', '&', '*', '()', '[]', '{}']
        prefixes = ['admin', 'user', 'test', 'demo', 'guest', 'root']
        
        for word in self.wordlists['common_passwords'][:1000]:  # Limit for performance
            # Try word with suffixes
            for suffix in suffixes:
                attempts += 1
                test_word = word + suffix
                if self._verify_hash(test_word, hash_value, hash_type):
                    return CrackResult(hash_value, hash_type, True, test_word, "hybrid_suffix", 0, attempts)
            
            # Try word with prefixes
            for prefix in prefixes:
                attempts += 1
                test_word = prefix + word
                if self._verify_hash(test_word, hash_value, hash_type):
                    return CrackResult(hash_value, hash_type, True, test_word, "hybrid_prefix", 0, attempts)
        
        return CrackResult(hash_value, hash_type, False, None, "hybrid", 0, attempts)
    
    def _mask_attack(self, hash_value: str, hash_type: HashType) -> CrackResult:
        """Mask attack with common patterns"""
        attempts = 0
        
        # Common patterns
        patterns = [
            r'^[a-z]{4}\d{4}$',  # word1234
            r'^\d{4}[a-z]{4}$',  # 1234word
            r'^[A-Z][a-z]+\d{2}$',  # Name12
            r'^\d{2}[A-Z][a-z]+$',  # 12Name
            r'^[a-z]+\d{2}[!@#$%^&*]$',  # word12!
        ]
        
        # This is a simplified implementation
        # In practice, you'd use tools like hashcat with mask files
        for pattern in patterns:
            # Generate words matching pattern
            for word in self._generate_pattern_words(pattern):
                attempts += 1
                if self._verify_hash(word, hash_value, hash_type):
                    return CrackResult(hash_value, hash_type, True, word, "mask", 0, attempts)
        
        return CrackResult(hash_value, hash_type, False, None, "mask", 0, attempts)
    
    def _verify_hash(self, plaintext: str, hash_value: str, hash_type: HashType) -> bool:
        """Verify if plaintext produces the given hash"""
        try:
            if hash_type == HashType.MD5:
                return hashlib.md5(plaintext.encode()).hexdigest() == hash_value
            elif hash_type == HashType.SHA1:
                return hashlib.sha1(plaintext.encode()).hexdigest() == hash_value
            elif hash_type == HashType.SHA256:
                return hashlib.sha256(plaintext.encode()).hexdigest() == hash_value
            elif hash_type == HashType.SHA512:
                return hashlib.sha512(plaintext.encode()).hexdigest() == hash_value
            elif hash_type == HashType.MYSQL:
                return self._verify_mysql_hash(plaintext, hash_value)
            elif hash_type == HashType.POSTGRESQL:
                return self._verify_postgresql_hash(plaintext, hash_value)
            elif hash_type == HashType.MSSQL:
                return self._verify_mssql_hash(plaintext, hash_value)
            elif hash_type == HashType.NTLM:
                return self._verify_ntlm_hash(plaintext, hash_value)
            elif hash_type == HashType.APACHE:
                return self._verify_apache_hash(plaintext, hash_value)
            elif hash_type == HashType.PHPBB:
                return self._verify_phpbb_hash(plaintext, hash_value)
            elif hash_type == HashType.DRUPAL:
                return self._verify_drupal_hash(plaintext, hash_value)
            
            return False
            
        except Exception as e:
            self.logger.debug(f"[-] Hash verification failed: {e}")
            return False
    
    def _verify_mysql_hash(self, plaintext: str, hash_value: str) -> bool:
        """Verify MySQL hash"""
        try:
            import hashlib
            # MySQL uses SHA1(SHA1(password))
            sha1_hash = hashlib.sha1(plaintext.encode()).hexdigest()
            double_sha1 = hashlib.sha1(sha1_hash.encode()).hexdigest()
            return double_sha1.upper() == hash_value.upper()
        except Exception:
            return False
    
    def _verify_postgresql_hash(self, plaintext: str, hash_value: str) -> bool:
        """Verify PostgreSQL hash"""
        try:
            import hashlib
            # PostgreSQL uses MD5 with salt
            if hash_value.startswith('md5'):
                salt = hash_value[3:]
                md5_hash = hashlib.md5((plaintext + 'postgres').encode()).hexdigest()
                return md5_hash == salt
            return False
        except Exception:
            return False
    
    def _verify_mssql_hash(self, plaintext: str, hash_value: str) -> bool:
        """Verify MSSQL hash"""
        try:
            import hashlib
            # MSSQL uses various hash types
            if len(hash_value) == 32:
                # MD5
                return hashlib.md5(plaintext.encode()).hexdigest().upper() == hash_value.upper()
            elif len(hash_value) == 40:
                # SHA1
                return hashlib.sha1(plaintext.encode()).hexdigest().upper() == hash_value.upper()
            return False
        except Exception:
            return False
    
    def _verify_ntlm_hash(self, plaintext: str, hash_value: str) -> bool:
        """Verify NTLM hash"""
        try:
            import hashlib
            # NTLM uses MD4
            md4_hash = hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
            return md4_hash.upper() == hash_value.upper()
        except Exception:
            return False
    
    def _verify_apache_hash(self, plaintext: str, hash_value: str) -> bool:
        """Verify Apache hash (bcrypt)"""
        try:
            import bcrypt
            return bcrypt.checkpw(plaintext.encode(), hash_value.encode())
        except Exception:
            return False
    
    def _verify_phpbb_hash(self, plaintext: str, hash_value: str) -> bool:
        """Verify PHPBB hash"""
        try:
            import hashlib
            # PHPBB uses MD5 with salt
            if hash_value.startswith('$P$'):
                salt = hash_value[3:11]
                md5_hash = hashlib.md5((salt + plaintext).encode()).hexdigest()
                return hash_value == f"$P${salt}{md5_hash}"
            return False
        except Exception:
            return False
    
    def _verify_drupal_hash(self, plaintext: str, hash_value: str) -> bool:
        """Verify Drupal hash"""
        try:
            import hashlib
            # Drupal uses SHA512 with salt
            if hash_value.startswith('$S$'):
                salt = hash_value[3:11]
                sha512_hash = hashlib.sha512((salt + plaintext).encode()).hexdigest()
                return hash_value == f"$S${salt}{sha512_hash}"
            return False
        except Exception:
            return False
    
    def _load_common_passwords(self) -> List[str]:
        """Load common passwords wordlist"""
        return [
            'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
            'admin', 'root', 'user', 'guest', 'test', 'demo', 'welcome',
            'letmein', 'monkey', 'dragon', 'master', 'hello', 'login',
            'princess', 'qwertyuiop', 'solo', 'passw0rd', 'starwars',
            'iloveyou', 'welcome123', 'admin123', 'root123', 'password1',
            '12345678', '1234567890', 'qwerty123', 'password12', 'admin1234'
        ]
    
    def _load_rockyou_wordlist(self) -> List[str]:
        """Load RockYou wordlist (simplified)"""
        # In practice, you'd load from the actual RockYou file
        return [
            '123456', 'password', '123456789', '12345678', '12345', '1234567',
            '1234567890', 'qwerty', 'abc123', '111111', '123123', 'admin',
            'letmein', 'welcome', 'monkey', '1234', 'dragon', 'password1',
            'master', 'hello', 'freedom', 'whatever', 'qazwsx', 'trustno1'
        ]
    
    def _load_names_wordlist(self) -> List[str]:
        """Load common names wordlist"""
        return [
            'john', 'jane', 'mike', 'sarah', 'david', 'lisa', 'chris', 'jennifer',
            'michael', 'jessica', 'robert', 'ashley', 'william', 'amanda', 'james',
            'stephanie', 'christopher', 'nicole', 'daniel', 'elizabeth', 'matthew',
            'michelle', 'anthony', 'kimberly', 'mark', 'donna', 'donald', 'carol',
            'steven', 'sandra', 'paul', 'dorothy', 'andrew', 'lisa', 'joshua',
            'nancy', 'kenneth', 'karen', 'kevin', 'betty', 'brian', 'helen'
        ]
    
    def _load_dates_wordlist(self) -> List[str]:
        """Load dates wordlist"""
        dates = []
        for year in range(1950, 2025):
            dates.append(str(year))
            for month in range(1, 13):
                dates.append(f"{year}{month:02d}")
                for day in range(1, 32):
                    dates.append(f"{year}{month:02d}{day:02d}")
        return dates[:1000]  # Limit for performance
    
    def _generate_pattern_words(self, pattern: str) -> List[str]:
        """Generate words matching a pattern"""
        # Simplified pattern generation
        words = []
        if pattern == r'^[a-z]{4}\d{4}$':
            for i in range(1000, 10000):
                words.append(f"word{i}")
        elif pattern == r'^\d{4}[a-z]{4}$':
            for i in range(1000, 10000):
                words.append(f"{i}word")
        return words[:100]  # Limit for performance
    
    def get_cracking_statistics(self) -> Dict[str, Any]:
        """Get hash cracking statistics"""
        return {
            'total_hashes': self.cracking_stats['total_hashes'],
            'cracked_hashes': self.cracking_stats['cracked_hashes'],
            'failed_hashes': self.cracking_stats['failed_hashes'],
            'success_rate': (self.cracking_stats['cracked_hashes'] / max(self.cracking_stats['total_hashes'], 1)) * 100,
            'total_time': self.cracking_stats['total_time'],
            'average_time_per_hash': self.cracking_stats['total_time'] / max(self.cracking_stats['total_hashes'], 1)
        }
    
    def export_cracked_hashes(self, filename: str):
        """Export cracked hashes to file"""
        try:
            with open(filename, 'w') as f:
                f.write("Hash,Plaintext,Method,Time\n")
                for hash_val, result in self.cracked_hashes.items():
                    if result.cracked:
                        f.write(f"{hash_val},{result.plaintext},{result.method},{result.time_taken}\n")
            self.logger.success(f"[+] Cracked hashes exported to {filename}")
        except Exception as e:
            self.logger.error(f"[-] Export failed: {e}")
