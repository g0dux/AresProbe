"""
AresProbe Response Comparer
Response comparison capabilities like Burp Comparer
"""

import difflib
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import hashlib
from collections import defaultdict

from .logger import Logger


class ComparisonType(Enum):
    """Types of comparisons"""
    WORD = "word"
    CHARACTER = "character"
    LINE = "line"
    BYTE = "byte"


@dataclass
class Difference:
    """Represents a difference between two responses"""
    type: str  # 'added', 'removed', 'modified'
    content: str
    position: int
    length: int
    context_before: str
    context_after: str
    significance: str  # 'low', 'medium', 'high', 'critical'


@dataclass
class ComparisonResult:
    """Result of response comparison"""
    response1: str
    response2: str
    differences: List[Difference]
    similarity_score: float
    total_differences: int
    critical_differences: int
    analysis: Dict[str, Any]
    recommendations: List[str]


class ResponseComparer:
    """
    Response comparison tool like Burp Comparer
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.comparison_history = []
        self.difference_patterns = self._load_difference_patterns()
    
    def compare_responses(self, response1: str, response2: str, 
                         comparison_type: ComparisonType = ComparisonType.WORD) -> ComparisonResult:
        """Compare two responses"""
        try:
            self.logger.info("[*] Comparing responses...")
            
            # Normalize responses
            norm_response1 = self._normalize_response(response1)
            norm_response2 = self._normalize_response(response2)
            
            # Find differences
            differences = self._find_differences(norm_response1, norm_response2, comparison_type)
            
            # Calculate similarity score
            similarity_score = self._calculate_similarity(norm_response1, norm_response2)
            
            # Analyze differences
            analysis = self._analyze_differences(differences)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(differences, analysis)
            
            result = ComparisonResult(
                response1=response1,
                response2=response2,
                differences=differences,
                similarity_score=similarity_score,
                total_differences=len(differences),
                critical_differences=len([d for d in differences if d.significance == 'critical']),
                analysis=analysis,
                recommendations=recommendations
            )
            
            self.comparison_history.append(result)
            
            self.logger.success(f"[+] Comparison completed: {len(differences)} differences found")
            
            return result
            
        except Exception as e:
            self.logger.error(f"[-] Comparison failed: {e}")
            return ComparisonResult(
                response1=response1,
                response2=response2,
                differences=[],
                similarity_score=0.0,
                total_differences=0,
                critical_differences=0,
                analysis={},
                recommendations=[f"Comparison failed: {str(e)}"]
            )
    
    def compare_multiple_responses(self, responses: List[str], 
                                 comparison_type: ComparisonType = ComparisonType.WORD) -> List[ComparisonResult]:
        """Compare multiple responses"""
        results = []
        
        for i in range(len(responses)):
            for j in range(i + 1, len(responses)):
                result = self.compare_responses(responses[i], responses[j], comparison_type)
                results.append(result)
        
        return results
    
    def _normalize_response(self, response: str) -> str:
        """Normalize response for comparison"""
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', response.strip())
        
        # Normalize line endings
        normalized = normalized.replace('\r\n', '\n').replace('\r', '\n')
        
        # Remove timestamps and dynamic content
        normalized = re.sub(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', '[TIMESTAMP]', normalized)
        normalized = re.sub(r'\d{13}', '[TIMESTAMP]', normalized)  # Unix timestamp
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '[UUID]', normalized)
        
        return normalized
    
    def _find_differences(self, response1: str, response2: str, 
                         comparison_type: ComparisonType) -> List[Difference]:
        """Find differences between responses"""
        differences = []
        
        if comparison_type == ComparisonType.WORD:
            differences = self._find_word_differences(response1, response2)
        elif comparison_type == ComparisonType.CHARACTER:
            differences = self._find_character_differences(response1, response2)
        elif comparison_type == ComparisonType.LINE:
            differences = self._find_line_differences(response1, response2)
        elif comparison_type == ComparisonType.BYTE:
            differences = self._find_byte_differences(response1, response2)
        
        return differences
    
    def _find_word_differences(self, response1: str, response2: str) -> List[Difference]:
        """Find word-level differences"""
        differences = []
        
        words1 = response1.split()
        words2 = response2.split()
        
        matcher = difflib.SequenceMatcher(None, words1, words2)
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'replace':
                # Modified words
                for k in range(i2 - i1):
                    if k < len(words1[i1:i2]) and k < len(words2[j1:j2]):
                        diff = Difference(
                            type='modified',
                            content=f"'{words1[i1 + k]}' -> '{words2[j1 + k]}'",
                            position=i1 + k,
                            length=1,
                            context_before=' '.join(words1[max(0, i1 + k - 3):i1 + k]),
                            context_after=' '.join(words2[j1 + k:min(len(words2), j1 + k + 4)]),
                            significance=self._assess_difference_significance(words1[i1 + k], words2[j1 + k])
                        )
                        differences.append(diff)
            elif tag == 'delete':
                # Removed words
                for k in range(i2 - i1):
                    diff = Difference(
                        type='removed',
                        content=words1[i1 + k],
                        position=i1 + k,
                        length=1,
                        context_before=' '.join(words1[max(0, i1 + k - 3):i1 + k]),
                        context_after=' '.join(words1[i1 + k:min(len(words1), i1 + k + 4)]),
                        significance=self._assess_difference_significance(words1[i1 + k], '')
                    )
                    differences.append(diff)
            elif tag == 'insert':
                # Added words
                for k in range(j2 - j1):
                    diff = Difference(
                        type='added',
                        content=words2[j1 + k],
                        position=j1 + k,
                        length=1,
                        context_before=' '.join(words2[max(0, j1 + k - 3):j1 + k]),
                        context_after=' '.join(words2[j1 + k:min(len(words2), j1 + k + 4)]),
                        significance=self._assess_difference_significance('', words2[j1 + k])
                    )
                    differences.append(diff)
        
        return differences
    
    def _find_character_differences(self, response1: str, response2: str) -> List[Difference]:
        """Find character-level differences"""
        differences = []
        
        matcher = difflib.SequenceMatcher(None, response1, response2)
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'replace':
                diff = Difference(
                    type='modified',
                    content=f"'{response1[i1:i2]}' -> '{response2[j1:j2]}'",
                    position=i1,
                    length=i2 - i1,
                    context_before=response1[max(0, i1 - 20):i1],
                    context_after=response2[j1:min(len(response2), j1 + 20)],
                    significance=self._assess_difference_significance(response1[i1:i2], response2[j1:j2])
                )
                differences.append(diff)
            elif tag == 'delete':
                diff = Difference(
                    type='removed',
                    content=response1[i1:i2],
                    position=i1,
                    length=i2 - i1,
                    context_before=response1[max(0, i1 - 20):i1],
                    context_after=response1[i1:min(len(response1), i1 + 20)],
                    significance=self._assess_difference_significance(response1[i1:i2], '')
                )
                differences.append(diff)
            elif tag == 'insert':
                diff = Difference(
                    type='added',
                    content=response2[j1:j2],
                    position=j1,
                    length=j2 - j1,
                    context_before=response2[max(0, j1 - 20):j1],
                    context_after=response2[j1:min(len(response2), j1 + 20)],
                    significance=self._assess_difference_significance('', response2[j1:j2])
                )
                differences.append(diff)
        
        return differences
    
    def _find_line_differences(self, response1: str, response2: str) -> List[Difference]:
        """Find line-level differences"""
        differences = []
        
        lines1 = response1.split('\n')
        lines2 = response2.split('\n')
        
        matcher = difflib.SequenceMatcher(None, lines1, lines2)
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'replace':
                for k in range(max(i2 - i1, j2 - j1)):
                    line1 = lines1[i1 + k] if i1 + k < i2 else ''
                    line2 = lines2[j1 + k] if j1 + k < j2 else ''
                    
                    diff = Difference(
                        type='modified',
                        content=f"Line {i1 + k + 1}: '{line1}' -> '{line2}'",
                        position=i1 + k,
                        length=1,
                        context_before=lines1[max(0, i1 + k - 2):i1 + k],
                        context_after=lines2[j1 + k:min(len(lines2), j1 + k + 3)],
                        significance=self._assess_difference_significance(line1, line2)
                    )
                    differences.append(diff)
            elif tag == 'delete':
                for k in range(i2 - i1):
                    diff = Difference(
                        type='removed',
                        content=f"Line {i1 + k + 1}: {lines1[i1 + k]}",
                        position=i1 + k,
                        length=1,
                        context_before=lines1[max(0, i1 + k - 2):i1 + k],
                        context_after=lines1[i1 + k:min(len(lines1), i1 + k + 3)],
                        significance=self._assess_difference_significance(lines1[i1 + k], '')
                    )
                    differences.append(diff)
            elif tag == 'insert':
                for k in range(j2 - j1):
                    diff = Difference(
                        type='added',
                        content=f"Line {j1 + k + 1}: {lines2[j1 + k]}",
                        position=j1 + k,
                        length=1,
                        context_before=lines2[max(0, j1 + k - 2):j1 + k],
                        context_after=lines2[j1 + k:min(len(lines2), j1 + k + 3)],
                        significance=self._assess_difference_significance('', lines2[j1 + k])
                    )
                    differences.append(diff)
        
        return differences
    
    def _find_byte_differences(self, response1: str, response2: str) -> List[Difference]:
        """Find byte-level differences"""
        differences = []
        
        bytes1 = response1.encode('utf-8')
        bytes2 = response2.encode('utf-8')
        
        matcher = difflib.SequenceMatcher(None, bytes1, bytes2)
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'replace':
                diff = Difference(
                    type='modified',
                    content=f"Bytes {i1}-{i2}: {bytes1[i1:i2].hex()} -> {bytes2[j1:j2].hex()}",
                    position=i1,
                    length=i2 - i1,
                    context_before=bytes1[max(0, i1 - 10):i1].hex(),
                    context_after=bytes2[j1:min(len(bytes2), j1 + 10)].hex(),
                    significance=self._assess_difference_significance(bytes1[i1:i2].hex(), bytes2[j1:j2].hex())
                )
                differences.append(diff)
            elif tag == 'delete':
                diff = Difference(
                    type='removed',
                    content=f"Bytes {i1}-{i2}: {bytes1[i1:i2].hex()}",
                    position=i1,
                    length=i2 - i1,
                    context_before=bytes1[max(0, i1 - 10):i1].hex(),
                    context_after=bytes1[i1:min(len(bytes1), i1 + 10)].hex(),
                    significance=self._assess_difference_significance(bytes1[i1:i2].hex(), '')
                )
                differences.append(diff)
            elif tag == 'insert':
                diff = Difference(
                    type='added',
                    content=f"Bytes {j1}-{j2}: {bytes2[j1:j2].hex()}",
                    position=j1,
                    length=j2 - j1,
                    context_before=bytes2[max(0, j1 - 10):j1].hex(),
                    context_after=bytes2[j1:min(len(bytes2), j1 + 10)].hex(),
                    significance=self._assess_difference_significance('', bytes2[j1:j2].hex())
                )
                differences.append(diff)
        
        return differences
    
    def _assess_difference_significance(self, old_content: str, new_content: str) -> str:
        """Assess the significance of a difference"""
        # Check for security-related patterns
        security_patterns = [
            r'password', r'secret', r'token', r'key', r'auth',
            r'admin', r'root', r'user', r'login', r'session',
            r'error', r'exception', r'warning', r'debug',
            r'sql', r'database', r'query', r'select', r'insert',
            r'<script', r'javascript:', r'onclick', r'onload',
            r'http://', r'https://', r'ftp://',
            r'file://', r'\\', r'../', r'..\\'
        ]
        
        combined_content = (old_content + new_content).lower()
        
        for pattern in security_patterns:
            if re.search(pattern, combined_content):
                return 'critical'
        
        # Check for structural changes
        if len(old_content) == 0 and len(new_content) > 0:
            return 'high'  # Addition
        elif len(old_content) > 0 and len(new_content) == 0:
            return 'high'  # Removal
        elif abs(len(old_content) - len(new_content)) > 100:
            return 'high'  # Large change
        
        # Check for content type changes
        if self._is_json(old_content) != self._is_json(new_content):
            return 'medium'
        if self._is_html(old_content) != self._is_html(new_content):
            return 'medium'
        if self._is_xml(old_content) != self._is_xml(new_content):
            return 'medium'
        
        return 'low'
    
    def _is_json(self, content: str) -> bool:
        """Check if content is JSON"""
        try:
            json.loads(content)
            return True
        except:
            return False
    
    def _is_html(self, content: str) -> bool:
        """Check if content is HTML"""
        return bool(re.search(r'<[a-zA-Z][^>]*>', content))
    
    def _is_xml(self, content: str) -> bool:
        """Check if content is XML"""
        return bool(re.search(r'<\?xml', content))
    
    def _calculate_similarity(self, response1: str, response2: str) -> float:
        """Calculate similarity score between responses"""
        matcher = difflib.SequenceMatcher(None, response1, response2)
        return matcher.ratio()
    
    def _analyze_differences(self, differences: List[Difference]) -> Dict[str, Any]:
        """Analyze differences for patterns and insights"""
        analysis = {
            'total_differences': len(differences),
            'difference_types': defaultdict(int),
            'significance_levels': defaultdict(int),
            'content_patterns': defaultdict(int),
            'position_distribution': [],
            'security_indicators': [],
            'structural_changes': []
        }
        
        for diff in differences:
            # Count difference types
            analysis['difference_types'][diff.type] += 1
            analysis['significance_levels'][diff.significance] += 1
            analysis['position_distribution'].append(diff.position)
            
            # Analyze content patterns
            if re.search(r'password|secret|token', diff.content.lower()):
                analysis['content_patterns']['authentication'] += 1
                analysis['security_indicators'].append('Authentication-related change')
            
            if re.search(r'error|exception|warning', diff.content.lower()):
                analysis['content_patterns']['error_handling'] += 1
                analysis['security_indicators'].append('Error handling change')
            
            if re.search(r'<script|javascript:', diff.content.lower()):
                analysis['content_patterns']['javascript'] += 1
                analysis['security_indicators'].append('JavaScript content change')
            
            if re.search(r'sql|database|query', diff.content.lower()):
                analysis['content_patterns']['database'] += 1
                analysis['security_indicators'].append('Database-related change')
            
            # Check for structural changes
            if diff.type == 'added' and len(diff.content) > 50:
                analysis['structural_changes'].append('Large content addition')
            elif diff.type == 'removed' and len(diff.content) > 50:
                analysis['structural_changes'].append('Large content removal')
        
        return analysis
    
    def _generate_recommendations(self, differences: List[Difference], 
                                analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on differences"""
        recommendations = []
        
        # Critical differences
        critical_count = analysis['significance_levels']['critical']
        if critical_count > 0:
            recommendations.append(f"CRITICAL: {critical_count} critical differences found - immediate investigation required")
        
        # Security indicators
        if analysis['security_indicators']:
            recommendations.append("SECURITY: Potential security-related changes detected")
            for indicator in set(analysis['security_indicators']):
                recommendations.append(f"  - {indicator}")
        
        # Authentication changes
        if analysis['content_patterns']['authentication'] > 0:
            recommendations.append("AUTHENTICATION: Changes to authentication-related content detected")
        
        # Error handling changes
        if analysis['content_patterns']['error_handling'] > 0:
            recommendations.append("ERROR HANDLING: Changes to error messages detected - potential information disclosure")
        
        # JavaScript changes
        if analysis['content_patterns']['javascript'] > 0:
            recommendations.append("JAVASCRIPT: Changes to JavaScript content detected - potential XSS vulnerability")
        
        # Database changes
        if analysis['content_patterns']['database'] > 0:
            recommendations.append("DATABASE: Changes to database-related content detected - potential SQL injection")
        
        # Structural changes
        if analysis['structural_changes']:
            recommendations.append("STRUCTURAL: Significant structural changes detected")
            for change in set(analysis['structural_changes']):
                recommendations.append(f"  - {change}")
        
        # General recommendations
        if len(differences) > 100:
            recommendations.append("VOLUME: Large number of differences - consider automated analysis")
        
        if analysis['significance_levels']['high'] > 10:
            recommendations.append("HIGH IMPACT: Multiple high-significance differences - detailed review recommended")
        
        return recommendations
    
    def _load_difference_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for difference analysis"""
        return {
            'security': [
                r'password', r'secret', r'token', r'key', r'auth',
                r'admin', r'root', r'user', r'login', r'session'
            ],
            'errors': [
                r'error', r'exception', r'warning', r'debug', r'fatal'
            ],
            'injection': [
                r'sql', r'database', r'query', r'select', r'insert',
                r'<script', r'javascript:', r'onclick', r'onload'
            ],
            'paths': [
                r'http://', r'https://', r'ftp://', r'file://',
                r'\\', r'../', r'..\\', r'/'
            ]
        }
    
    def get_comparison_history(self) -> List[ComparisonResult]:
        """Get comparison history"""
        return self.comparison_history
    
    def clear_history(self):
        """Clear comparison history"""
        self.comparison_history = []
        self.logger.info("[*] Comparison history cleared")
    
    def export_results(self, filename: str):
        """Export comparison results to file"""
        try:
            export_data = {
                'comparison_history': [result.__dict__ for result in self.comparison_history],
                'total_comparisons': len(self.comparison_history),
                'total_differences': sum(result.total_differences for result in self.comparison_history),
                'critical_differences': sum(result.critical_differences for result in self.comparison_history)
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.success(f"[+] Comparison results exported to {filename}")
            
        except Exception as e:
            self.logger.error(f"[-] Export failed: {e}")
