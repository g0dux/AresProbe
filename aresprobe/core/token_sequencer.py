"""
AresProbe Token Sequencer
Token randomness analysis like Burp Sequencer
"""

import math
import statistics
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import time
import random

from .logger import Logger


class EntropyMethod(Enum):
    """Entropy calculation methods"""
    SHANNON = "shannon"
    MINIMUM = "minimum"
    MAXIMUM = "maximum"
    MEAN = "mean"


@dataclass
class TokenAnalysis:
    """Token analysis result"""
    token: str
    entropy: float
    character_frequency: Dict[str, int]
    character_probability: Dict[str, float]
    pattern_score: float
    randomness_score: float
    is_predictable: bool
    prediction_confidence: float


@dataclass
class SequenceAnalysis:
    """Sequence analysis result"""
    tokens: List[str]
    total_entropy: float
    average_entropy: float
    entropy_variance: float
    pattern_detection: List[Dict[str, Any]]
    predictability_score: float
    randomness_quality: str
    recommendations: List[str]


class TokenSequencer:
    """
    Token randomness analyzer like Burp Sequencer
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.analyzed_tokens = []
        self.sequence_analyses = []
    
    def analyze_token(self, token: str) -> TokenAnalysis:
        """Analyze a single token for randomness"""
        try:
            self.logger.info(f"[*] Analyzing token: {token[:20]}...")
            
            # Calculate character frequency
            char_freq = self._calculate_character_frequency(token)
            
            # Calculate character probabilities
            char_prob = self._calculate_character_probabilities(char_freq, len(token))
            
            # Calculate entropy
            entropy = self._calculate_entropy(char_prob)
            
            # Detect patterns
            pattern_score = self._detect_patterns(token)
            
            # Calculate randomness score
            randomness_score = self._calculate_randomness_score(entropy, pattern_score)
            
            # Determine if predictable
            is_predictable = self._is_predictable(entropy, pattern_score, randomness_score)
            
            # Calculate prediction confidence
            prediction_confidence = self._calculate_prediction_confidence(entropy, pattern_score)
            
            analysis = TokenAnalysis(
                token=token,
                entropy=entropy,
                character_frequency=char_freq,
                character_probability=char_prob,
                pattern_score=pattern_score,
                randomness_score=randomness_score,
                is_predictable=is_predictable,
                prediction_confidence=prediction_confidence
            )
            
            self.analyzed_tokens.append(analysis)
            
            if is_predictable:
                self.logger.warning(f"[!] Token appears predictable: {token[:20]}...")
            else:
                self.logger.success(f"[+] Token appears random: {token[:20]}...")
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"[-] Token analysis failed: {e}")
            return TokenAnalysis(
                token=token,
                entropy=0.0,
                character_frequency={},
                character_probability={},
                pattern_score=0.0,
                randomness_score=0.0,
                is_predictable=True,
                prediction_confidence=1.0
            )
    
    def analyze_sequence(self, tokens: List[str]) -> SequenceAnalysis:
        """Analyze a sequence of tokens"""
        try:
            self.logger.info(f"[*] Analyzing sequence of {len(tokens)} tokens")
            
            # Analyze each token
            token_analyses = [self.analyze_token(token) for token in tokens]
            
            # Calculate sequence statistics
            entropies = [analysis.entropy for analysis in token_analyses]
            total_entropy = sum(entropies)
            average_entropy = statistics.mean(entropies) if entropies else 0.0
            entropy_variance = statistics.variance(entropies) if len(entropies) > 1 else 0.0
            
            # Detect patterns across sequence
            pattern_detection = self._detect_sequence_patterns(tokens)
            
            # Calculate overall predictability
            predictability_score = self._calculate_sequence_predictability(token_analyses)
            
            # Determine randomness quality
            randomness_quality = self._determine_randomness_quality(average_entropy, entropy_variance, predictability_score)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(token_analyses, pattern_detection, randomness_quality)
            
            analysis = SequenceAnalysis(
                tokens=tokens,
                total_entropy=total_entropy,
                average_entropy=average_entropy,
                entropy_variance=entropy_variance,
                pattern_detection=pattern_detection,
                predictability_score=predictability_score,
                randomness_quality=randomness_quality,
                recommendations=recommendations
            )
            
            self.sequence_analyses.append(analysis)
            
            self.logger.success(f"[+] Sequence analysis completed: {randomness_quality} quality")
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"[-] Sequence analysis failed: {e}")
            return SequenceAnalysis(
                tokens=tokens,
                total_entropy=0.0,
                average_entropy=0.0,
                entropy_variance=0.0,
                pattern_detection=[],
                predictability_score=1.0,
                randomness_quality="unknown",
                recommendations=["Analysis failed"]
            )
    
    def _calculate_character_frequency(self, token: str) -> Dict[str, int]:
        """Calculate character frequency in token"""
        frequency = {}
        for char in token:
            frequency[char] = frequency.get(char, 0) + 1
        return frequency
    
    def _calculate_character_probabilities(self, char_freq: Dict[str, int], token_length: int) -> Dict[str, float]:
        """Calculate character probabilities"""
        probabilities = {}
        for char, count in char_freq.items():
            probabilities[char] = count / token_length
        return probabilities
    
    def _calculate_entropy(self, char_prob: Dict[str, float]) -> float:
        """Calculate Shannon entropy"""
        entropy = 0.0
        for prob in char_prob.values():
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return entropy
    
    def _detect_patterns(self, token: str) -> float:
        """Detect patterns in token (lower score = more random)"""
        pattern_score = 0.0
        
        # Check for repeated characters
        char_counts = {}
        for char in token:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        max_repetition = max(char_counts.values()) if char_counts else 0
        if max_repetition > len(token) * 0.3:  # More than 30% repetition
            pattern_score += 0.3
        
        # Check for sequential patterns
        if self._has_sequential_pattern(token):
            pattern_score += 0.2
        
        # Check for common patterns
        if self._has_common_patterns(token):
            pattern_score += 0.2
        
        # Check for keyboard patterns
        if self._has_keyboard_pattern(token):
            pattern_score += 0.2
        
        # Check for dictionary words
        if self._has_dictionary_words(token):
            pattern_score += 0.1
        
        return min(pattern_score, 1.0)
    
    def _has_sequential_pattern(self, token: str) -> bool:
        """Check for sequential patterns (123, abc, etc.)"""
        # Check numeric sequences
        if re.search(r'\d{3,}', token):
            return True
        
        # Check alphabetic sequences
        if re.search(r'[a-z]{3,}', token.lower()):
            return True
        
        # Check reverse sequences
        if re.search(r'[a-z]{3,}', token.lower()[::-1]):
            return True
        
        return False
    
    def _has_common_patterns(self, token: str) -> bool:
        """Check for common patterns"""
        common_patterns = [
            r'^\d{4}$',  # 4 digits
            r'^\d{6}$',  # 6 digits
            r'^\d{8}$',  # 8 digits
            r'^[a-z]{3}\d{3}$',  # 3 letters + 3 digits
            r'^\d{3}[a-z]{3}$',  # 3 digits + 3 letters
            r'^[a-z]{2}\d{4}$',  # 2 letters + 4 digits
            r'^\d{4}[a-z]{2}$',  # 4 digits + 2 letters
        ]
        
        for pattern in common_patterns:
            if re.match(pattern, token.lower()):
                return True
        
        return False
    
    def _has_keyboard_pattern(self, token: str) -> bool:
        """Check for keyboard patterns"""
        keyboard_rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            '1234567890'
        ]
        
        token_lower = token.lower()
        
        for row in keyboard_rows:
            if len(token_lower) >= 3:
                for i in range(len(row) - 2):
                    if row[i:i+3] in token_lower:
                        return True
        
        return False
    
    def _has_dictionary_words(self, token: str) -> bool:
        """Check for dictionary words"""
        common_words = [
            'admin', 'user', 'test', 'demo', 'guest', 'root',
            'password', 'login', 'welcome', 'hello', 'world',
            'company', 'corp', 'inc', 'ltd', 'llc'
        ]
        
        token_lower = token.lower()
        
        for word in common_words:
            if word in token_lower:
                return True
        
        return False
    
    def _calculate_randomness_score(self, entropy: float, pattern_score: float) -> float:
        """Calculate overall randomness score"""
        # Normalize entropy (max entropy for 95 printable ASCII chars is ~6.57)
        normalized_entropy = min(entropy / 6.57, 1.0)
        
        # Combine entropy and pattern score
        randomness_score = normalized_entropy * (1.0 - pattern_score)
        
        return min(max(randomness_score, 0.0), 1.0)
    
    def _is_predictable(self, entropy: float, pattern_score: float, randomness_score: float) -> bool:
        """Determine if token is predictable"""
        # Low entropy indicates predictability
        if entropy < 3.0:
            return True
        
        # High pattern score indicates predictability
        if pattern_score > 0.5:
            return True
        
        # Low randomness score indicates predictability
        if randomness_score < 0.3:
            return True
        
        return False
    
    def _calculate_prediction_confidence(self, entropy: float, pattern_score: float) -> float:
        """Calculate confidence in prediction"""
        # Higher entropy = lower confidence in prediction
        entropy_factor = 1.0 - min(entropy / 6.57, 1.0)
        
        # Higher pattern score = higher confidence in prediction
        pattern_factor = pattern_score
        
        # Combine factors
        confidence = (entropy_factor + pattern_factor) / 2.0
        
        return min(max(confidence, 0.0), 1.0)
    
    def _detect_sequence_patterns(self, tokens: List[str]) -> List[Dict[str, Any]]:
        """Detect patterns across token sequence"""
        patterns = []
        
        # Check for incremental patterns
        if self._has_incremental_pattern(tokens):
            patterns.append({
                'type': 'incremental',
                'description': 'Tokens follow incremental pattern',
                'severity': 'high'
            })
        
        # Check for time-based patterns
        if self._has_time_based_pattern(tokens):
            patterns.append({
                'type': 'time_based',
                'description': 'Tokens appear time-based',
                'severity': 'high'
            })
        
        # Check for repeating patterns
        if self._has_repeating_pattern(tokens):
            patterns.append({
                'type': 'repeating',
                'description': 'Tokens repeat in sequence',
                'severity': 'medium'
            })
        
        # Check for length patterns
        if self._has_length_pattern(tokens):
            patterns.append({
                'type': 'length',
                'description': 'Tokens follow length pattern',
                'severity': 'low'
            })
        
        return patterns
    
    def _has_incremental_pattern(self, tokens: List[str]) -> bool:
        """Check for incremental patterns"""
        if len(tokens) < 3:
            return False
        
        # Check numeric increments
        numeric_tokens = []
        for token in tokens:
            if token.isdigit():
                numeric_tokens.append(int(token))
        
        if len(numeric_tokens) >= 3:
            diffs = [numeric_tokens[i+1] - numeric_tokens[i] for i in range(len(numeric_tokens)-1)]
            if len(set(diffs)) == 1:  # All differences are the same
                return True
        
        return False
    
    def _has_time_based_pattern(self, tokens: List[str]) -> bool:
        """Check for time-based patterns"""
        if len(tokens) < 3:
            return False
        
        # Check for timestamp-like patterns
        timestamp_patterns = [
            r'^\d{10}$',  # Unix timestamp
            r'^\d{13}$',  # Unix timestamp with milliseconds
            r'^\d{4}\d{2}\d{2}$',  # YYYYMMDD
            r'^\d{4}\d{2}\d{2}\d{2}\d{2}\d{2}$',  # YYYYMMDDHHMMSS
        ]
        
        timestamp_count = 0
        for token in tokens:
            for pattern in timestamp_patterns:
                if re.match(pattern, token):
                    timestamp_count += 1
                    break
        
        return timestamp_count >= len(tokens) * 0.7  # 70% are timestamps
    
    def _has_repeating_pattern(self, tokens: List[str]) -> bool:
        """Check for repeating patterns"""
        if len(tokens) < 6:
            return False
        
        # Check for simple repetition
        for i in range(1, len(tokens) // 2 + 1):
            pattern = tokens[:i]
            if all(tokens[j:j+i] == pattern for j in range(i, len(tokens), i)):
                return True
        
        return False
    
    def _has_length_pattern(self, tokens: List[str]) -> bool:
        """Check for length patterns"""
        if len(tokens) < 3:
            return False
        
        lengths = [len(token) for token in tokens]
        
        # Check for consistent length
        if len(set(lengths)) == 1:
            return True
        
        # Check for incremental length
        length_diffs = [lengths[i+1] - lengths[i] for i in range(len(lengths)-1)]
        if len(set(length_diffs)) == 1:
            return True
        
        return False
    
    def _calculate_sequence_predictability(self, token_analyses: List[TokenAnalysis]) -> float:
        """Calculate overall sequence predictability"""
        if not token_analyses:
            return 1.0
        
        # Average predictability of individual tokens
        avg_predictability = sum(analysis.prediction_confidence for analysis in token_analyses) / len(token_analyses)
        
        # Factor in pattern detection
        pattern_factor = 0.0
        for analysis in self.sequence_analyses:
            if analysis.pattern_detection:
                pattern_factor += 0.2
        
        total_predictability = min(avg_predictability + pattern_factor, 1.0)
        
        return total_predictability
    
    def _determine_randomness_quality(self, avg_entropy: float, entropy_variance: float, predictability: float) -> str:
        """Determine randomness quality"""
        if predictability > 0.8:
            return "very_poor"
        elif predictability > 0.6:
            return "poor"
        elif predictability > 0.4:
            return "fair"
        elif predictability > 0.2:
            return "good"
        else:
            return "excellent"
    
    def _generate_recommendations(self, token_analyses: List[TokenAnalysis], 
                                pattern_detection: List[Dict[str, Any]], 
                                randomness_quality: str) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if randomness_quality in ["very_poor", "poor"]:
            recommendations.append("CRITICAL: Token generation is highly predictable")
            recommendations.append("Implement cryptographically secure random number generator")
            recommendations.append("Use longer token lengths (minimum 32 characters)")
            recommendations.append("Include multiple character sets (uppercase, lowercase, numbers, symbols)")
        
        elif randomness_quality == "fair":
            recommendations.append("WARNING: Token generation could be improved")
            recommendations.append("Consider increasing token length")
            recommendations.append("Review random number generation algorithm")
        
        # Pattern-specific recommendations
        for pattern in pattern_detection:
            if pattern['type'] == 'incremental':
                recommendations.append("CRITICAL: Avoid incremental token generation")
            elif pattern['type'] == 'time_based':
                recommendations.append("WARNING: Avoid time-based token generation")
            elif pattern['type'] == 'repeating':
                recommendations.append("WARNING: Avoid repeating token patterns")
        
        # Entropy recommendations
        low_entropy_tokens = [analysis for analysis in token_analyses if analysis.entropy < 3.0]
        if low_entropy_tokens:
            recommendations.append(f"WARNING: {len(low_entropy_tokens)} tokens have low entropy")
        
        return recommendations
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        if not self.analyzed_tokens:
            return {}
        
        entropies = [analysis.entropy for analysis in self.analyzed_tokens]
        randomness_scores = [analysis.randomness_score for analysis in self.analyzed_tokens]
        
        return {
            'total_tokens_analyzed': len(self.analyzed_tokens),
            'average_entropy': statistics.mean(entropies),
            'entropy_variance': statistics.variance(entropies) if len(entropies) > 1 else 0.0,
            'average_randomness_score': statistics.mean(randomness_scores),
            'predictable_tokens': len([a for a in self.analyzed_tokens if a.is_predictable]),
            'total_sequences_analyzed': len(self.sequence_analyses)
        }
    
    def export_analysis(self, filename: str):
        """Export analysis results to file"""
        try:
            import json
            
            export_data = {
                'token_analyses': [analysis.__dict__ for analysis in self.analyzed_tokens],
                'sequence_analyses': [analysis.__dict__ for analysis in self.sequence_analyses],
                'statistics': self.get_analysis_statistics()
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.success(f"[+] Analysis results exported to {filename}")
            
        except Exception as e:
            self.logger.error(f"[-] Export failed: {e}")
