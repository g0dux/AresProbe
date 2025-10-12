"""
AresProbe AI Security Engine
Advanced vulnerability prediction and adaptive payload generation
"""

import asyncio
import json
import pickle
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from pathlib import Path
import time
import hashlib
import re
from collections import defaultdict, Counter
import logging

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

from .logger import Logger
from .async_engine import AsyncEngine, RequestResult


@dataclass
class VulnerabilityPattern:
    """Pattern for vulnerability prediction"""
    name: str
    pattern_type: str  # 'regex', 'behavioral', 'response', 'header'
    pattern: str
    confidence: float
    description: str
    false_positive_rate: float = 0.0
    true_positive_rate: float = 1.0


@dataclass
class PayloadTemplate:
    """Template for adaptive payload generation"""
    name: str
    category: str  # 'sql_injection', 'xss', 'command_injection', etc.
    template: str
    parameters: List[str] = field(default_factory=list)
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    effectiveness_score: float = 0.0
    usage_count: int = 0


@dataclass
class TargetProfile:
    """Profile of a target for adaptive testing"""
    url: str
    technology_stack: List[str] = field(default_factory=list)
    response_headers: Dict[str, str] = field(default_factory=dict)
    error_patterns: List[str] = field(default_factory=list)
    success_patterns: List[str] = field(default_factory=list)
    vulnerability_history: List[str] = field(default_factory=list)
    payload_effectiveness: Dict[str, float] = field(default_factory=dict)
    last_scan: float = 0.0
    scan_count: int = 0


class VulnerabilityPredictor:
    """AI-powered vulnerability prediction system"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.patterns: Dict[str, List[VulnerabilityPattern]] = defaultdict(list)
        self.models: Dict[str, Any] = {}
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.training_data = []
        self.is_trained = False
        
        # Load existing patterns
        self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Load default vulnerability patterns"""
        # SQL Injection patterns
        sql_patterns = [
            VulnerabilityPattern(
                name="SQL Error Pattern",
                pattern_type="response",
                pattern=r"(?i)(mysql|postgresql|sqlite|oracle).*error|syntax.*error|invalid.*query",
                confidence=0.8,
                description="Database error messages indicating SQL injection possibility"
            ),
            VulnerabilityPattern(
                name="SQL Time-based Pattern",
                pattern_type="behavioral",
                pattern="response_time_delay",
                confidence=0.7,
                description="Response time delays indicating time-based SQL injection"
            )
        ]
        
        # XSS patterns
        xss_patterns = [
            VulnerabilityPattern(
                name="XSS Reflection Pattern",
                pattern_type="response",
                pattern=r"<script[^>]*>.*</script>",
                confidence=0.9,
                description="Script tags in response indicating XSS vulnerability"
            ),
            VulnerabilityPattern(
                name="XSS Event Handler Pattern",
                pattern_type="response",
                pattern=r"on\w+\s*=\s*['\"][^'\"]*['\"]",
                confidence=0.8,
                description="Event handlers in response indicating XSS vulnerability"
            )
        ]
        
        # Command Injection patterns
        cmd_patterns = [
            VulnerabilityPattern(
                name="Command Error Pattern",
                pattern_type="response",
                pattern=r"(?i)(command not found|syntax error|permission denied)",
                confidence=0.8,
                description="Command execution errors indicating command injection"
            )
        ]
        
        self.patterns['sql_injection'] = sql_patterns
        self.patterns['xss'] = xss_patterns
        self.patterns['command_injection'] = cmd_patterns
    
    def add_pattern(self, vuln_type: str, pattern: VulnerabilityPattern):
        """Add a new vulnerability pattern"""
        self.patterns[vuln_type].append(pattern)
        self.logger.info(f"[+] Added pattern for {vuln_type}: {pattern.name}")
    
    def predict_vulnerability(self, target_profile: TargetProfile, vuln_type: str) -> Dict[str, Any]:
        """Predict vulnerability likelihood"""
        predictions = {
            'vulnerability_type': vuln_type,
            'confidence': 0.0,
            'indicators': [],
            'risk_score': 0.0,
            'recommended_payloads': []
        }
        
        # Pattern-based prediction
        pattern_confidence = self._pattern_based_prediction(target_profile, vuln_type)
        
        # ML-based prediction
        ml_confidence = self._ml_based_prediction(target_profile, vuln_type)
        
        # Historical prediction
        historical_confidence = self._historical_prediction(target_profile, vuln_type)
        
        # Combine predictions
        predictions['confidence'] = (pattern_confidence * 0.4 + 
                                   ml_confidence * 0.4 + 
                                   historical_confidence * 0.2)
        
        predictions['risk_score'] = self._calculate_risk_score(target_profile, vuln_type)
        
        return predictions
    
    def _pattern_based_prediction(self, target: TargetProfile, vuln_type: str) -> float:
        """Pattern-based vulnerability prediction"""
        if vuln_type not in self.patterns:
            return 0.0
        
        confidence_scores = []
        
        for pattern in self.patterns[vuln_type]:
            if pattern.pattern_type == 'response':
                # Check response patterns
                for response_text in target.success_patterns + target.error_patterns:
                    if re.search(pattern.pattern, response_text, re.IGNORECASE):
                        confidence_scores.append(pattern.confidence)
            
            elif pattern.pattern_type == 'behavioral':
                # Check behavioral patterns
                if pattern.pattern == 'response_time_delay':
                    # This would be implemented based on actual response time data
                    pass
            
            elif pattern.pattern_type == 'header':
                # Check header patterns
                for header_name, header_value in target.response_headers.items():
                    if re.search(pattern.pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                        confidence_scores.append(pattern.confidence)
        
        return max(confidence_scores) if confidence_scores else 0.0
    
    def _ml_based_prediction(self, target: TargetProfile, vuln_type: str) -> float:
        """ML-based vulnerability prediction"""
        if not self.is_trained:
            return 0.0
        
        # Create feature vector from target profile
        features = self._extract_features(target)
        
        if vuln_type in self.models:
            try:
                prediction = self.models[vuln_type].predict_proba([features])[0]
                return prediction[1] if len(prediction) > 1 else prediction[0]
            except Exception as e:
                self.logger.error(f"[-] ML prediction error: {e}")
                return 0.0
        
        return 0.0
    
    def _historical_prediction(self, target: TargetProfile, vuln_type: str) -> float:
        """Historical vulnerability prediction"""
        if vuln_type in target.vulnerability_history:
            # If this vulnerability was found before, higher confidence
            return 0.8
        
        # Check similar technology stacks
        tech_stack_similarity = self._calculate_tech_stack_similarity(target)
        return tech_stack_similarity * 0.3
    
    def _extract_features(self, target: TargetProfile) -> List[float]:
        """Extract features from target profile for ML"""
        features = []
        
        # Technology stack features
        tech_features = [0.0] * 20  # Common technologies
        tech_mapping = {
            'apache': 0, 'nginx': 1, 'iis': 2, 'tomcat': 3,
            'php': 4, 'asp': 5, 'jsp': 6, 'python': 7,
            'mysql': 8, 'postgresql': 9, 'oracle': 10,
            'javascript': 11, 'jquery': 12, 'angular': 13,
            'react': 14, 'vue': 15, 'bootstrap': 16
        }
        
        for tech in target.technology_stack:
            tech_lower = tech.lower()
            for key, idx in tech_mapping.items():
                if key in tech_lower:
                    tech_features[idx] = 1.0
        
        features.extend(tech_features)
        
        # Response header features
        header_features = [
            len(target.response_headers),
            1.0 if 'server' in target.response_headers else 0.0,
            1.0 if 'x-powered-by' in target.response_headers else 0.0,
            1.0 if 'x-aspnet-version' in target.response_headers else 0.0
        ]
        features.extend(header_features)
        
        # Error pattern features
        error_features = [
            len(target.error_patterns),
            len(target.success_patterns)
        ]
        features.extend(error_features)
        
        # Scan history features
        history_features = [
            target.scan_count,
            time.time() - target.last_scan if target.last_scan > 0 else 0
        ]
        features.extend(history_features)
        
        return features
    
    def _calculate_risk_score(self, target: TargetProfile, vuln_type: str) -> float:
        """Calculate overall risk score"""
        risk_factors = []
        
        # Technology risk factors
        high_risk_techs = ['php', 'asp', 'jsp', 'mysql', 'oracle']
        for tech in target.technology_stack:
            if any(risk_tech in tech.lower() for risk_tech in high_risk_techs):
                risk_factors.append(0.2)
        
        # Header risk factors
        risky_headers = ['x-powered-by', 'server', 'x-aspnet-version']
        for header in risky_headers:
            if header in target.response_headers:
                risk_factors.append(0.1)
        
        # Historical risk factors
        if target.vulnerability_history:
            risk_factors.append(0.3)
        
        return min(1.0, sum(risk_factors))
    
    def _calculate_tech_stack_similarity(self, target: TargetProfile) -> float:
        """Calculate similarity with known vulnerable tech stacks"""
        try:
            # Known vulnerable tech stack patterns
            vulnerable_patterns = {
                'php': {
                    'versions': ['5.6', '7.0', '7.1', '7.2'],
                    'frameworks': ['wordpress', 'drupal', 'joomla', 'magento'],
                    'risk_score': 0.8
                },
                'apache': {
                    'versions': ['2.2', '2.4.0', '2.4.1', '2.4.2'],
                    'modules': ['mod_rewrite', 'mod_ssl', 'mod_php'],
                    'risk_score': 0.6
                },
                'nginx': {
                    'versions': ['1.10', '1.11', '1.12', '1.13'],
                    'config_issues': ['missing_security_headers', 'default_config'],
                    'risk_score': 0.5
                },
                'mysql': {
                    'versions': ['5.5', '5.6', '5.7.0', '5.7.1'],
                    'config_issues': ['weak_passwords', 'default_privileges'],
                    'risk_score': 0.7
                },
                'wordpress': {
                    'versions': ['4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9'],
                    'plugins': ['outdated_plugins', 'vulnerable_plugins'],
                    'risk_score': 0.9
                }
            }
            
            similarity_score = 0.0
            total_checks = 0
            
            # Check web server
            if target.web_server:
                server_lower = target.web_server.lower()
                for tech, pattern in vulnerable_patterns.items():
                    if tech in server_lower:
                        similarity_score += pattern['risk_score']
                        total_checks += 1
                        
                        # Check version if available
                        if target.web_server_version:
                            version = target.web_server_version
                            if version in pattern.get('versions', []):
                                similarity_score += 0.2  # Bonus for exact version match
                        
                        break
            
            # Check database
            if target.database:
                db_lower = target.database.lower()
                for tech, pattern in vulnerable_patterns.items():
                    if tech in db_lower:
                        similarity_score += pattern['risk_score']
                        total_checks += 1
                        
                        # Check version if available
                        if target.database_version:
                            version = target.database_version
                            if version in pattern.get('versions', []):
                                similarity_score += 0.2
                        
                        break
            
            # Check CMS/Framework
            if target.cms:
                cms_lower = target.cms.lower()
                for tech, pattern in vulnerable_patterns.items():
                    if tech in cms_lower:
                        similarity_score += pattern['risk_score']
                        total_checks += 1
                        
                        # Check version if available
                        if target.cms_version:
                            version = target.cms_version
                            if version in pattern.get('versions', []):
                                similarity_score += 0.2
                        
                        break
            
            # Check programming language
            if target.programming_language:
                lang_lower = target.programming_language.lower()
                for tech, pattern in vulnerable_patterns.items():
                    if tech in lang_lower:
                        similarity_score += pattern['risk_score']
                        total_checks += 1
                        break
            
            # Normalize score
            if total_checks > 0:
                similarity_score = min(similarity_score / total_checks, 1.0)
            else:
                similarity_score = 0.1  # Default low risk for unknown tech stacks
            
            return similarity_score
            
        except Exception as e:
            self.logger.debug(f"[-] Error calculating tech stack similarity: {e}")
            return 0.1  # Default low risk on error
    
    def train_model(self, vuln_type: str, training_data: List[Tuple[TargetProfile, bool]]):
        """Train ML model for vulnerability prediction"""
        if not training_data:
            return
        
        # Extract features and labels
        X = [self._extract_features(profile) for profile, _ in training_data]
        y = [1 if vulnerable else 0 for _, vulnerable in training_data]
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train ensemble model
        models = {
            'rf': RandomForestClassifier(n_estimators=100, random_state=42),
            'gb': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'svm': SVC(probability=True, random_state=42)
        }
        
        best_model = None
        best_score = 0.0
        
        for name, model in models.items():
            model.fit(X_train, y_train)
            score = model.score(X_test, y_test)
            
            if score > best_score:
                best_score = score
                best_model = model
        
        self.models[vuln_type] = best_model
        self.logger.info(f"[+] Trained {vuln_type} model with accuracy: {best_score:.3f}")
    
    def save_model(self, vuln_type: str, filepath: str):
        """Save trained model"""
        if vuln_type in self.models:
            joblib.dump(self.models[vuln_type], filepath)
            self.logger.info(f"[+] Saved {vuln_type} model to {filepath}")
    
    def load_model(self, vuln_type: str, filepath: str):
        """Load trained model"""
        try:
            self.models[vuln_type] = joblib.load(filepath)
            self.logger.info(f"[+] Loaded {vuln_type} model from {filepath}")
        except Exception as e:
            self.logger.error(f"[-] Failed to load model: {e}")


class AdaptivePayloadGenerator:
    """AI-powered adaptive payload generation system"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.payload_templates: Dict[str, List[PayloadTemplate]] = defaultdict(list)
        self.effectiveness_history: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.target_profiles: Dict[str, TargetProfile] = {}
        
        # Load default payload templates
        self._load_default_templates()
    
    def _load_default_templates(self):
        """Load default payload templates"""
        # SQL Injection templates
        sql_templates = [
            PayloadTemplate(
                name="Basic Union",
                category="sql_injection",
                template="' UNION SELECT {columns} FROM {table} --",
                parameters=["columns", "table"],
                success_indicators=["data", "username", "password"],
                failure_indicators=["error", "syntax", "invalid"]
            ),
            PayloadTemplate(
                name="Time-based Blind",
                category="sql_injection",
                template="' AND SLEEP({delay}) --",
                parameters=["delay"],
                success_indicators=["time_delay"],
                failure_indicators=["immediate_response"]
            ),
            PayloadTemplate(
                name="Boolean-based Blind",
                category="sql_injection",
                template="' AND {condition} --",
                parameters=["condition"],
                success_indicators=["true_response"],
                failure_indicators=["false_response"]
            )
        ]
        
        # XSS templates
        xss_templates = [
            PayloadTemplate(
                name="Basic Script",
                category="xss",
                template="<script>alert('{message}')</script>",
                parameters=["message"],
                success_indicators=["alert", "script"],
                failure_indicators=["filtered", "encoded"]
            ),
            PayloadTemplate(
                name="Event Handler",
                category="xss",
                template="' onmouseover='alert({message})' '",
                parameters=["message"],
                success_indicators=["onmouseover", "alert"],
                failure_indicators=["filtered"]
            )
        ]
        
        # Command Injection templates
        cmd_templates = [
            PayloadTemplate(
                name="Basic Command",
                category="command_injection",
                template="; {command}",
                parameters=["command"],
                success_indicators=["command_output", "executed"],
                failure_indicators=["command not found", "permission denied"]
            )
        ]
        
        self.payload_templates['sql_injection'] = sql_templates
        self.payload_templates['xss'] = xss_templates
        self.payload_templates['command_injection'] = cmd_templates
    
    def generate_payloads(self, target_profile: TargetProfile, vuln_type: str, count: int = 10) -> List[str]:
        """Generate adaptive payloads for a target"""
        if vuln_type not in self.payload_templates:
            return []
        
        # Update target profile
        self.target_profiles[target_profile.url] = target_profile
        
        # Get best performing templates
        templates = self._get_best_templates(target_profile, vuln_type)
        
        # Generate payloads
        payloads = []
        for template in templates[:count]:
            payload = self._generate_payload_from_template(template, target_profile)
            if payload:
                payloads.append(payload)
        
        return payloads
    
    def _get_best_templates(self, target: TargetProfile, vuln_type: str) -> List[PayloadTemplate]:
        """Get best performing templates for target"""
        templates = self.payload_templates[vuln_type].copy()
        
        # Sort by effectiveness for this target
        target_url = target.url
        if target_url in self.effectiveness_history:
            effectiveness = self.effectiveness_history[target_url]
            templates.sort(key=lambda t: effectiveness.get(t.name, t.effectiveness_score), reverse=True)
        else:
            # Sort by global effectiveness
            templates.sort(key=lambda t: t.effectiveness_score, reverse=True)
        
        return templates
    
    def _generate_payload_from_template(self, template: PayloadTemplate, target: TargetProfile) -> Optional[str]:
        """Generate payload from template"""
        try:
            payload = template.template
            
            # Replace parameters based on target profile
            for param in template.parameters:
                if param == "columns":
                    payload = payload.replace("{columns}", "1,2,3,4,5")
                elif param == "table":
                    payload = payload.replace("{table}", "users")
                elif param == "delay":
                    payload = payload.replace("{delay}", "5")
                elif param == "condition":
                    payload = payload.replace("{condition}", "1=1")
                elif param == "message":
                    payload = payload.replace("{message}", "XSS")
                elif param == "command":
                    payload = payload.replace("{command}", "whoami")
            
            return payload
            
        except Exception as e:
            self.logger.error(f"[-] Failed to generate payload: {e}")
            return None
    
    def update_effectiveness(self, target_url: str, payload: str, vuln_type: str, success: bool):
        """Update payload effectiveness based on results"""
        # Find matching template
        template = self._find_template_by_payload(payload, vuln_type)
        if not template:
            return
        
        # Update effectiveness
        if target_url not in self.effectiveness_history:
            self.effectiveness_history[target_url] = {}
        
        current_score = self.effectiveness_history[target_url].get(template.name, template.effectiveness_score)
        
        if success:
            new_score = min(1.0, current_score + 0.1)
        else:
            new_score = max(0.0, current_score - 0.05)
        
        self.effectiveness_history[target_url][template.name] = new_score
        template.effectiveness_score = new_score
        template.usage_count += 1
    
    def _find_template_by_payload(self, payload: str, vuln_type: str) -> Optional[PayloadTemplate]:
        """Find template that generated a payload"""
        for template in self.payload_templates[vuln_type]:
            if self._payload_matches_template(payload, template):
                return template
        return None
    
    def _payload_matches_template(self, payload: str, template: PayloadTemplate) -> bool:
        """Check if payload matches template pattern"""
        # Simple pattern matching - could be improved
        template_pattern = template.template
        for param in template.parameters:
            template_pattern = template_pattern.replace(f"{{{param}}}", ".*")
        
        return bool(re.match(template_pattern, payload))
    
    def get_payload_statistics(self) -> Dict[str, Any]:
        """Get payload generation statistics"""
        stats = {
            'total_templates': sum(len(templates) for templates in self.payload_templates.values()),
            'vulnerability_types': list(self.payload_templates.keys()),
            'target_profiles': len(self.target_profiles),
            'effectiveness_history': len(self.effectiveness_history)
        }
        
        # Template effectiveness
        template_stats = {}
        for vuln_type, templates in self.payload_templates.items():
            template_stats[vuln_type] = {
                'count': len(templates),
                'avg_effectiveness': sum(t.effectiveness_score for t in templates) / len(templates),
                'total_usage': sum(t.usage_count for t in templates)
            }
        
        stats['template_stats'] = template_stats
        return stats


class AISecurityEngine:
    """Main AI Security Engine combining prediction and payload generation"""
    
    def __init__(self, logger: Optional[Logger] = None):
        self.logger = logger or Logger()
        self.predictor = VulnerabilityPredictor(self.logger)
        self.payload_generator = AdaptivePayloadGenerator(self.logger)
        self.target_profiles: Dict[str, TargetProfile] = {}
        self.scan_history: List[Dict[str, Any]] = []
        
    def create_target_profile(self, url: str, response: RequestResult) -> TargetProfile:
        """Create target profile from response"""
        profile = TargetProfile(url=url)
        
        # Extract technology stack from headers
        profile.response_headers = response.headers
        profile.technology_stack = self._extract_technology_stack(response.headers)
        
        # Extract patterns from response
        content = response.content.decode('utf-8', errors='ignore')
        profile.error_patterns = self._extract_error_patterns(content)
        profile.success_patterns = self._extract_success_patterns(content)
        
        profile.last_scan = time.time()
        profile.scan_count = 1
        
        self.target_profiles[url] = profile
        return profile
    
    def _extract_technology_stack(self, headers: Dict[str, str]) -> List[str]:
        """Extract technology stack from response headers"""
        tech_stack = []
        
        # Server header
        if 'server' in headers:
            tech_stack.append(headers['server'])
        
        # X-Powered-By header
        if 'x-powered-by' in headers:
            tech_stack.append(headers['x-powered-by'])
        
        # X-AspNet-Version header
        if 'x-aspnet-version' in headers:
            tech_stack.append(f"ASP.NET {headers['x-aspnet-version']}")
        
        # X-Generator header
        if 'x-generator' in headers:
            tech_stack.append(headers['x-generator'])
        
        return tech_stack
    
    def _extract_error_patterns(self, content: str) -> List[str]:
        """Extract error patterns from response content"""
        error_patterns = []
        
        # Common error patterns
        error_regexes = [
            r'(?i)error.*\d+',
            r'(?i)exception.*occurred',
            r'(?i)fatal.*error',
            r'(?i)warning.*mysql',
            r'(?i)syntax.*error',
            r'(?i)undefined.*variable'
        ]
        
        for pattern in error_regexes:
            matches = re.findall(pattern, content)
            error_patterns.extend(matches)
        
        return error_patterns
    
    def _extract_success_patterns(self, content: str) -> List[str]:
        """Extract success patterns from response content"""
        success_patterns = []
        
        # Common success patterns
        success_regexes = [
            r'(?i)success',
            r'(?i)welcome',
            r'(?i)login.*successful',
            r'(?i)data.*retrieved'
        ]
        
        for pattern in success_regexes:
            matches = re.findall(pattern, content)
            success_patterns.extend(matches)
        
        return success_patterns
    
    async def analyze_target(self, url: str, async_engine: AsyncEngine) -> Dict[str, Any]:
        """Analyze target and predict vulnerabilities"""
        try:
            # Get initial response
            response = await async_engine.get(url)
            
            # Create or update target profile
            if url in self.target_profiles:
                profile = self.target_profiles[url]
                profile.scan_count += 1
                profile.last_scan = time.time()
            else:
                profile = self.create_target_profile(url, response)
            
            # Predict vulnerabilities
            predictions = {}
            for vuln_type in ['sql_injection', 'xss', 'command_injection']:
                predictions[vuln_type] = self.predictor.predict_vulnerability(profile, vuln_type)
            
            # Generate adaptive payloads for high-confidence predictions
            adaptive_payloads = {}
            for vuln_type, prediction in predictions.items():
                if prediction['confidence'] > 0.7:
                    adaptive_payloads[vuln_type] = self.payload_generator.generate_payloads(
                        profile, vuln_type, count=5
                    )
            
            analysis_result = {
                'target_url': url,
                'target_profile': profile,
                'predictions': predictions,
                'adaptive_payloads': adaptive_payloads,
                'analysis_timestamp': time.time()
            }
            
            self.scan_history.append(analysis_result)
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"[-] Failed to analyze target {url}: {e}")
            return {}
    
    def update_vulnerability_found(self, url: str, vuln_type: str, payload: str, success: bool):
        """Update system when vulnerability is found"""
        if url in self.target_profiles:
            profile = self.target_profiles[url]
            
            if success and vuln_type not in profile.vulnerability_history:
                profile.vulnerability_history.append(vuln_type)
            
            # Update payload effectiveness
            self.payload_generator.update_effectiveness(url, payload, vuln_type, success)
            
            # Update target profile
            if vuln_type not in profile.payload_effectiveness:
                profile.payload_effectiveness[vuln_type] = {}
            
            current_effectiveness = profile.payload_effectiveness[vuln_type].get(payload, 0.5)
            new_effectiveness = min(1.0, current_effectiveness + 0.1) if success else max(0.0, current_effectiveness - 0.05)
            profile.payload_effectiveness[vuln_type][payload] = new_effectiveness
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of AI analysis capabilities"""
        return {
            'total_targets': len(self.target_profiles),
            'total_scans': len(self.scan_history),
            'prediction_accuracy': self._calculate_prediction_accuracy(),
            'payload_statistics': self.payload_generator.get_payload_statistics(),
            'vulnerability_patterns': {
                vuln_type: len(patterns) 
                for vuln_type, patterns in self.predictor.patterns.items()
            }
        }
    
    def _calculate_prediction_accuracy(self) -> float:
        """Calculate prediction accuracy based on scan history"""
        if not self.scan_history:
            return 0.0
        
        correct_predictions = 0
        total_predictions = 0
        
        for scan in self.scan_history:
            for vuln_type, prediction in scan['predictions'].items():
                total_predictions += 1
                
                # Compare prediction against actual scan results
                actual_vulnerabilities = scan.get('actual_vulnerabilities', {})
                actual_found = actual_vulnerabilities.get(vuln_type, False)
                
                # Determine if prediction was correct
                predicted_confidence = prediction.get('confidence', 0.0)
                predicted_found = predicted_confidence > 0.5
                
                # Check if prediction matches reality
                if predicted_found == actual_found:
                    correct_predictions += 1
                elif predicted_confidence > 0.7 and actual_found:
                    # High confidence prediction that was correct
                    correct_predictions += 1
                elif predicted_confidence < 0.3 and not actual_found:
                    # Low confidence prediction that was correct
                    correct_predictions += 1
        
        return correct_predictions / total_predictions if total_predictions > 0 else 0.0
    
    def save_models(self, directory: str):
        """Save AI models to directory"""
        model_dir = Path(directory)
        model_dir.mkdir(exist_ok=True)
        
        # Save vulnerability predictor models
        for vuln_type, model in self.predictor.models.items():
            model_path = model_dir / f"{vuln_type}_model.pkl"
            self.predictor.save_model(vuln_type, str(model_path))
        
        # Save target profiles
        profiles_path = model_dir / "target_profiles.pkl"
        with open(profiles_path, 'wb') as f:
            pickle.dump(self.target_profiles, f)
        
        self.logger.info(f"[+] AI models saved to {directory}")
    
    def load_models(self, directory: str):
        """Load AI models from directory"""
        model_dir = Path(directory)
        
        if not model_dir.exists():
            self.logger.warning(f"[-] Model directory not found: {directory}")
            return
        
        # Load target profiles
        profiles_path = model_dir / "target_profiles.pkl"
        if profiles_path.exists():
            with open(profiles_path, 'rb') as f:
                self.target_profiles = pickle.load(f)
        
        self.logger.info(f"[+] AI models loaded from {directory}")
