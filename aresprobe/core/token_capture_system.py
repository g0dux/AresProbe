"""
AresProbe Token Capture System
Advanced token capture and analysis integration
"""

import re
import json
import time
import asyncio
import base64
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
from .advanced_token_sequencer import AdvancedTokenSequencer, TokenType, AnalysisType
from .advanced_proxy_interception import AdvancedProxyInterception, InterceptedRequest, InterceptedResponse

class CaptureMode(Enum):
    """Token capture modes"""
    AUTOMATIC = "automatic"
    MANUAL = "manual"
    TARGETED = "targeted"
    CONTINUOUS = "continuous"

class TokenPattern(Enum):
    """Token patterns"""
    SESSION_ID = r'(?:session[_-]?id|jsessionid|phpsessid|aspnet_sessionid)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})'
    CSRF_TOKEN = r'(?:csrf[_-]?token|_token|authenticity_token)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})'
    JWT = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
    API_KEY = r'(?:api[_-]?key|apikey)\s*[:=]\s*([a-zA-Z0-9]{20,})'
    AUTH_TOKEN = r'(?:auth[_-]?token|access[_-]?token)\s*[:=]\s*([a-zA-Z0-9+/=]{20,})'
    REFRESH_TOKEN = r'(?:refresh[_-]?token)\s*[:=]\s*([a-zA-Z0-9+/=]{20,})'
    ID_TOKEN = r'(?:id[_-]?token)\s*[:=]\s*([a-zA-Z0-9+/=]{20,})'
    NONCE = r'(?:nonce)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})'
    STATE = r'(?:state)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})'
    CODE = r'(?:code)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})'
    CHALLENGE = r'(?:challenge)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})'
    CAPTCHA = r'(?:captcha[_-]?token|captcha)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})'
    CUSTOM = r''

@dataclass
class CapturedToken:
    """Captured token information"""
    value: str
    token_type: TokenType
    source: str
    context: Dict[str, Any]
    timestamp: float
    request_id: str
    response_id: str
    metadata: Dict[str, Any]

class TokenCaptureSystem:
    """Advanced token capture and analysis system"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.sequencer = AdvancedTokenSequencer(logger)
        self.captured_tokens = []
        self.capture_mode = CaptureMode.AUTOMATIC
        self.enabled_patterns = list(TokenPattern)
        self.custom_patterns = []
        self.capture_callbacks = []
        
        # Capture configuration
        self.auto_analyze = True
        self.analysis_interval = 60  # seconds
        self.min_tokens_for_analysis = 10
        self.max_tokens_per_analysis = 1000
        
        # Initialize patterns
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize token patterns"""
        self.patterns = {
            TokenType.SESSION_ID: [
                r'(?:session[_-]?id|jsessionid|phpsessid|aspnet_sessionid)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})',
                r'Set-Cookie:\s*[^=]*=([a-zA-Z0-9+/=]{16,})',
                r'Cookie:\s*[^=]*=([a-zA-Z0-9+/=]{16,})'
            ],
            TokenType.CSRF_TOKEN: [
                r'(?:csrf[_-]?token|_token|authenticity_token)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})',
                r'<input[^>]*name=["\'](?:csrf[_-]?token|_token|authenticity_token)["\'][^>]*value=["\']([^"\']+)["\']',
                r'<meta[^>]*name=["\'](?:csrf[_-]?token|_token|authenticity_token)["\'][^>]*content=["\']([^"\']+)["\']'
            ],
            TokenType.JWT: [
                r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                r'(?:jwt|token)\s*[:=]\s*(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'
            ],
            TokenType.API_KEY: [
                r'(?:api[_-]?key|apikey)\s*[:=]\s*([a-zA-Z0-9]{20,})',
                r'Authorization:\s*Bearer\s+([a-zA-Z0-9]{20,})',
                r'X-API-Key:\s*([a-zA-Z0-9]{20,})'
            ],
            TokenType.AUTH_TOKEN: [
                r'(?:auth[_-]?token|access[_-]?token)\s*[:=]\s*([a-zA-Z0-9+/=]{20,})',
                r'Authorization:\s*Bearer\s+([a-zA-Z0-9+/=]{20,})',
                r'X-Auth-Token:\s*([a-zA-Z0-9+/=]{20,})'
            ],
            TokenType.REFRESH_TOKEN: [
                r'(?:refresh[_-]?token)\s*[:=]\s*([a-zA-Z0-9+/=]{20,})',
                r'refresh_token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{20,})'
            ],
            TokenType.ID_TOKEN: [
                r'(?:id[_-]?token)\s*[:=]\s*([a-zA-Z0-9+/=]{20,})',
                r'id_token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{20,})'
            ],
            TokenType.NONCE: [
                r'(?:nonce)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})',
                r'<input[^>]*name=["\']nonce["\'][^>]*value=["\']([^"\']+)["\']'
            ],
            TokenType.STATE: [
                r'(?:state)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})',
                r'state["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{16,})'
            ],
            TokenType.CODE: [
                r'(?:code)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})',
                r'code["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{16,})'
            ],
            TokenType.CHALLENGE: [
                r'(?:challenge)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})',
                r'challenge["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{16,})'
            ],
            TokenType.CAPTCHA: [
                r'(?:captcha[_-]?token|captcha)\s*[:=]\s*([a-zA-Z0-9+/=]{16,})',
                r'<input[^>]*name=["\']captcha["\'][^>]*value=["\']([^"\']+)["\']'
            ]
        }
    
    def start_capture(self, proxy: AdvancedProxyInterception) -> bool:
        """Start token capture from proxy"""
        try:
            if self.logger:
                self.logger.success("[+] Starting token capture system")
                self.logger.success(f"[+] Capture mode: {self.capture_mode.value}")
                self.logger.success(f"[+] Enabled patterns: {len(self.enabled_patterns)}")
                self.logger.success(f"[+] Auto-analyze: {self.auto_analyze}")
            
            # Add proxy listener
            proxy.add_listener(self._on_request_response)
            
            # Start analysis timer if auto-analyze is enabled
            if self.auto_analyze:
                self._start_analysis_timer()
            
            return True
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Token capture start failed: {e}")
            return False
    
    def stop_capture(self, proxy: AdvancedProxyInterception):
        """Stop token capture"""
        try:
            # Remove proxy listener
            proxy.remove_listener(self._on_request_response)
            
            if self.logger:
                self.logger.success("[+] Token capture system stopped")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Token capture stop failed: {e}")
    
    def _on_request_response(self, request: InterceptedRequest, response: InterceptedResponse):
        """Handle intercepted request/response"""
        try:
            # Extract tokens from request
            self._extract_tokens_from_request(request)
            
            # Extract tokens from response
            self._extract_tokens_from_response(response)
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Token extraction failed: {e}")
    
    def _extract_tokens_from_request(self, request: InterceptedRequest):
        """Extract tokens from request"""
        try:
            # Extract from headers
            for header_name, header_value in request.headers.items():
                self._extract_tokens_from_text(header_value, f"request_header_{header_name}", request)
            
            # Extract from parameters
            for param_name, param_value in request.parameters.items():
                self._extract_tokens_from_text(param_value, f"request_param_{param_name}", request)
            
            # Extract from body
            if request.body:
                body_text = request.body.decode('utf-8', errors='ignore')
                self._extract_tokens_from_text(body_text, "request_body", request)
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Request token extraction failed: {e}")
    
    def _extract_tokens_from_response(self, response: InterceptedResponse):
        """Extract tokens from response"""
        try:
            # Extract from headers
            for header_name, header_value in response.headers.items():
                self._extract_tokens_from_text(header_value, f"response_header_{header_name}", response)
            
            # Extract from body
            if response.body:
                body_text = response.body.decode('utf-8', errors='ignore')
                self._extract_tokens_from_text(body_text, "response_body", response)
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Response token extraction failed: {e}")
    
    def _extract_tokens_from_text(self, text: str, source: str, context: Any):
        """Extract tokens from text using patterns"""
        try:
            for token_type, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, text, re.IGNORECASE)
                    for match in matches:
                        token_value = match.group(1) if match.groups() else match.group(0)
                        
                        # Validate token
                        if self._validate_token(token_value, token_type):
                            # Create captured token
                            captured_token = CapturedToken(
                                value=token_value,
                                token_type=token_type,
                                source=source,
                                context=self._extract_context(context),
                                timestamp=time.time(),
                                request_id=getattr(context, 'request_id', ''),
                                response_id=getattr(context, 'response_id', ''),
                                metadata=self._extract_metadata(token_value, token_type)
                            )
                            
                            # Add to captured tokens
                            self.captured_tokens.append(captured_token)
                            
                            # Add to sequencer
                            self.sequencer.add_sample(
                                token_value,
                                source,
                                self._extract_context(context),
                                self._extract_metadata(token_value, token_type)
                            )
                            
                            # Call callbacks
                            for callback in self.capture_callbacks:
                                try:
                                    callback(captured_token)
                                except Exception as e:
                                    if self.logger:
                                        self.logger.debug(f"[-] Callback failed: {e}")
                            
                            if self.logger:
                                self.logger.info(f"[+] Captured {token_type.value}: {token_value[:20]}...")
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Token extraction from text failed: {e}")
    
    def _validate_token(self, token: str, token_type: TokenType) -> bool:
        """Validate captured token"""
        try:
            # Basic validation
            if not token or len(token) < 8:
                return False
            
            # Type-specific validation
            if token_type == TokenType.JWT:
                return self._validate_jwt(token)
            elif token_type == TokenType.SESSION_ID:
                return self._validate_session_id(token)
            elif token_type == TokenType.CSRF_TOKEN:
                return self._validate_csrf_token(token)
            elif token_type == TokenType.API_KEY:
                return self._validate_api_key(token)
            else:
                return True
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[-] Token validation failed: {e}")
            return False
    
    def _validate_jwt(self, token: str) -> bool:
        """Validate JWT token"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
            
            # Check if parts are base64 encoded
            for part in parts:
                try:
                    base64.b64decode(part + '==')  # Add padding
                except:
                    return False
            
            return True
        except:
            return False
    
    def _validate_session_id(self, token: str) -> bool:
        """Validate session ID token"""
        try:
            # Check if it's a valid session ID format
            if len(token) < 16 or len(token) > 128:
                return False
            
            # Check if it contains valid characters
            if not re.match(r'^[a-zA-Z0-9+/=_-]+$', token):
                return False
            
            return True
        except:
            return False
    
    def _validate_csrf_token(self, token: str) -> bool:
        """Validate CSRF token"""
        try:
            # Check if it's a valid CSRF token format
            if len(token) < 16 or len(token) > 128:
                return False
            
            # Check if it contains valid characters
            if not re.match(r'^[a-zA-Z0-9+/=_-]+$', token):
                return False
            
            return True
        except:
            return False
    
    def _validate_api_key(self, token: str) -> bool:
        """Validate API key token"""
        try:
            # Check if it's a valid API key format
            if len(token) < 20 or len(token) > 256:
                return False
            
            # Check if it contains valid characters
            if not re.match(r'^[a-zA-Z0-9_-]+$', token):
                return False
            
            return True
        except:
            return False
    
    def _extract_context(self, context: Any) -> Dict[str, Any]:
        """Extract context from request/response"""
        try:
            if hasattr(context, 'url'):
                return {
                    'url': context.url,
                    'method': getattr(context, 'method', ''),
                    'headers': getattr(context, 'headers', {}),
                    'timestamp': getattr(context, 'timestamp', time.time())
                }
            return {}
        except:
            return {}
    
    def _extract_metadata(self, token: str, token_type: TokenType) -> Dict[str, Any]:
        """Extract metadata from token"""
        try:
            metadata = {
                'length': len(token),
                'entropy': self._calculate_entropy(token),
                'character_set': self._get_character_set(token),
                'encoding': self._detect_encoding(token)
            }
            
            if token_type == TokenType.JWT:
                metadata.update(self._extract_jwt_metadata(token))
            
            return metadata
        except:
            return {}
    
    def _calculate_entropy(self, token: str) -> float:
        """Calculate token entropy"""
        try:
            from collections import Counter
            import math
            
            char_counts = Counter(token)
            total_chars = len(token)
            entropy = 0
            
            for count in char_counts.values():
                probability = count / total_chars
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            return entropy
        except:
            return 0
    
    def _get_character_set(self, token: str) -> str:
        """Get character set of token"""
        try:
            if re.match(r'^[a-zA-Z0-9]+$', token):
                return 'alphanumeric'
            elif re.match(r'^[a-zA-Z0-9+/=]+$', token):
                return 'base64'
            elif re.match(r'^[a-fA-F0-9]+$', token):
                return 'hex'
            else:
                return 'mixed'
        except:
            return 'unknown'
    
    def _detect_encoding(self, token: str) -> str:
        """Detect token encoding"""
        try:
            if re.match(r'^[a-zA-Z0-9+/=]+$', token):
                return 'base64'
            elif re.match(r'^[a-fA-F0-9]+$', token):
                return 'hex'
            else:
                return 'unknown'
        except:
            return 'unknown'
    
    def _extract_jwt_metadata(self, token: str) -> Dict[str, Any]:
        """Extract JWT metadata"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {}
            
            # Decode header
            header = json.loads(base64.b64decode(parts[0] + '=='))
            
            # Decode payload
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            
            return {
                'header': header,
                'payload': payload,
                'algorithm': header.get('alg', ''),
                'expires': payload.get('exp', 0),
                'issued_at': payload.get('iat', 0)
            }
        except:
            return {}
    
    def _start_analysis_timer(self):
        """Start analysis timer"""
        try:
            def analysis_loop():
                while True:
                    time.sleep(self.analysis_interval)
                    
                    if len(self.captured_tokens) >= self.min_tokens_for_analysis:
                        self._run_analysis()
            
            analysis_thread = threading.Thread(target=analysis_loop)
            analysis_thread.daemon = True
            analysis_thread.start()
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Analysis timer start failed: {e}")
    
    def _run_analysis(self):
        """Run token analysis"""
        try:
            if self.logger:
                self.logger.info("[*] Running token analysis")
            
            # Group tokens by type
            tokens_by_type = {}
            for token in self.captured_tokens:
                token_type = token.token_type
                if token_type not in tokens_by_type:
                    tokens_by_type[token_type] = []
                tokens_by_type[token_type].append(token)
            
            # Analyze each token type
            for token_type, tokens in tokens_by_type.items():
                if len(tokens) >= self.min_tokens_for_analysis:
                    # Add tokens to sequencer
                    for token in tokens:
                        self.sequencer.add_sample(
                            token.value,
                            token.source,
                            token.context,
                            token.metadata
                        )
                    
                    # Run analysis
                    results = self.sequencer.analyze_tokens(token_type)
                    
                    if self.logger:
                        self.logger.success(f"[+] Analysis completed for {token_type.value}: {len(results)} results")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"[-] Token analysis failed: {e}")
    
    def add_capture_callback(self, callback: Callable[[CapturedToken], None]):
        """Add token capture callback"""
        self.capture_callbacks.append(callback)
        if self.logger:
            self.logger.info("[*] Token capture callback added")
    
    def add_custom_pattern(self, token_type: TokenType, pattern: str):
        """Add custom token pattern"""
        if token_type not in self.patterns:
            self.patterns[token_type] = []
        
        self.patterns[token_type].append(pattern)
        if self.logger:
            self.logger.info(f"[*] Custom pattern added for {token_type.value}")
    
    def get_captured_tokens(self) -> List[CapturedToken]:
        """Get captured tokens"""
        return self.captured_tokens
    
    def get_analysis_results(self) -> List[Any]:
        """Get analysis results"""
        return self.sequencer.get_results()
    
    def clear_data(self):
        """Clear all data"""
        self.captured_tokens.clear()
        self.sequencer.clear_data()
        if self.logger:
            self.logger.info("[*] Token capture data cleared")
    
    def set_capture_mode(self, mode: CaptureMode):
        """Set capture mode"""
        self.capture_mode = mode
        if self.logger:
            self.logger.info(f"[*] Capture mode set to: {mode.value}")
    
    def set_auto_analyze(self, enabled: bool):
        """Set auto-analyze mode"""
        self.auto_analyze = enabled
        if self.logger:
            self.logger.info(f"[*] Auto-analyze: {'enabled' if enabled else 'disabled'}")
    
    def set_analysis_interval(self, interval: int):
        """Set analysis interval"""
        self.analysis_interval = interval
        if self.logger:
            self.logger.info(f"[*] Analysis interval set to: {interval} seconds")
