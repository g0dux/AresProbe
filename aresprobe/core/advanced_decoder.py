"""
AresProbe Advanced Decoder
Advanced decoding capabilities like Burp Decoder
"""

import base64
import urllib.parse
import html
import binascii
import gzip
import zlib
import json
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import jwt
import hashlib
import hmac

from .logger import Logger


class EncodingType(Enum):
    """Supported encoding types"""
    BASE64 = "base64"
    BASE32 = "base32"
    BASE16 = "base16"
    URL = "url"
    HTML = "html"
    HEX = "hex"
    BINARY = "binary"
    GZIP = "gzip"
    ZLIB = "zlib"
    JWT = "jwt"
    UNICODE = "unicode"
    ROT13 = "rot13"
    CAESAR = "caesar"
    REVERSE = "reverse"
    XOR = "xor"


@dataclass
class DecodeResult:
    """Result of decoding operation"""
    original: str
    decoded: str
    encoding_type: EncodingType
    success: bool
    confidence: float
    error_message: Optional[str]
    metadata: Dict[str, Any]


class AdvancedDecoder:
    """
    Advanced decoder with capabilities similar to Burp Decoder
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.decode_history = []
        self.auto_detection_patterns = self._load_auto_detection_patterns()
    
    def auto_decode(self, data: str) -> List[DecodeResult]:
        """Automatically detect and decode data"""
        try:
            self.logger.info(f"[*] Auto-decoding data: {data[:50]}...")
            
            results = []
            detected_encodings = self._detect_encodings(data)
            
            for encoding_type in detected_encodings:
                result = self.decode(data, encoding_type)
                if result.success:
                    results.append(result)
            
            # If no encodings detected, try common ones
            if not results:
                common_encodings = [
                    EncodingType.BASE64,
                    EncodingType.URL,
                    EncodingType.HTML,
                    EncodingType.HEX
                ]
                
                for encoding_type in common_encodings:
                    result = self.decode(data, encoding_type)
                    if result.success:
                        results.append(result)
            
            self.logger.success(f"[+] Auto-decode completed: {len(results)} successful decodings")
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Auto-decode failed: {e}")
            return []
    
    def decode(self, data: str, encoding_type: EncodingType) -> DecodeResult:
        """Decode data with specific encoding type"""
        try:
            self.logger.debug(f"[*] Decoding with {encoding_type.value}")
            
            decoded_data = ""
            success = False
            confidence = 0.0
            error_message = None
            metadata = {}
            
            if encoding_type == EncodingType.BASE64:
                decoded_data, success, confidence, metadata = self._decode_base64(data)
            elif encoding_type == EncodingType.BASE32:
                decoded_data, success, confidence, metadata = self._decode_base32(data)
            elif encoding_type == EncodingType.BASE16:
                decoded_data, success, confidence, metadata = self._decode_base16(data)
            elif encoding_type == EncodingType.URL:
                decoded_data, success, confidence, metadata = self._decode_url(data)
            elif encoding_type == EncodingType.HTML:
                decoded_data, success, confidence, metadata = self._decode_html(data)
            elif encoding_type == EncodingType.HEX:
                decoded_data, success, confidence, metadata = self._decode_hex(data)
            elif encoding_type == EncodingType.BINARY:
                decoded_data, success, confidence, metadata = self._decode_binary(data)
            elif encoding_type == EncodingType.GZIP:
                decoded_data, success, confidence, metadata = self._decode_gzip(data)
            elif encoding_type == EncodingType.ZLIB:
                decoded_data, success, confidence, metadata = self._decode_zlib(data)
            elif encoding_type == EncodingType.JWT:
                decoded_data, success, confidence, metadata = self._decode_jwt(data)
            elif encoding_type == EncodingType.UNICODE:
                decoded_data, success, confidence, metadata = self._decode_unicode(data)
            elif encoding_type == EncodingType.ROT13:
                decoded_data, success, confidence, metadata = self._decode_rot13(data)
            elif encoding_type == EncodingType.CAESAR:
                decoded_data, success, confidence, metadata = self._decode_caesar(data)
            elif encoding_type == EncodingType.REVERSE:
                decoded_data, success, confidence, metadata = self._decode_reverse(data)
            elif encoding_type == EncodingType.XOR:
                decoded_data, success, confidence, metadata = self._decode_xor(data)
            
            result = DecodeResult(
                original=data,
                decoded=decoded_data,
                encoding_type=encoding_type,
                success=success,
                confidence=confidence,
                error_message=error_message,
                metadata=metadata
            )
            
            self.decode_history.append(result)
            
            if success:
                self.logger.success(f"[+] Successfully decoded with {encoding_type.value}")
            else:
                self.logger.debug(f"[-] Failed to decode with {encoding_type.value}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"[-] Decode failed: {e}")
            return DecodeResult(
                original=data,
                decoded="",
                encoding_type=encoding_type,
                success=False,
                confidence=0.0,
                error_message=str(e),
                metadata={}
            )
    
    def encode(self, data: str, encoding_type: EncodingType) -> str:
        """Encode data with specific encoding type"""
        try:
            if encoding_type == EncodingType.BASE64:
                return base64.b64encode(data.encode()).decode()
            elif encoding_type == EncodingType.BASE32:
                return base64.b32encode(data.encode()).decode()
            elif encoding_type == EncodingType.BASE16:
                return base64.b16encode(data.encode()).decode()
            elif encoding_type == EncodingType.URL:
                return urllib.parse.quote(data)
            elif encoding_type == EncodingType.HTML:
                return html.escape(data)
            elif encoding_type == EncodingType.HEX:
                return data.encode().hex()
            elif encoding_type == EncodingType.BINARY:
                return ' '.join(format(ord(c), '08b') for c in data)
            elif encoding_type == EncodingType.UNICODE:
                return ''.join(f'\\u{ord(c):04x}' for c in data)
            elif encoding_type == EncodingType.ROT13:
                return self._encode_rot13(data)
            elif encoding_type == EncodingType.CAESAR:
                return self._encode_caesar(data, 3)
            elif encoding_type == EncodingType.REVERSE:
                return data[::-1]
            else:
                return data
                
        except Exception as e:
            self.logger.error(f"[-] Encode failed: {e}")
            return data
    
    def _detect_encodings(self, data: str) -> List[EncodingType]:
        """Detect possible encodings in data"""
        detected = []
        
        for pattern, encoding_type in self.auto_detection_patterns.items():
            if re.search(pattern, data, re.IGNORECASE):
                detected.append(encoding_type)
        
        return detected
    
    def _load_auto_detection_patterns(self) -> Dict[str, EncodingType]:
        """Load patterns for auto-detection"""
        return {
            r'^[A-Za-z0-9+/]+=*$': EncodingType.BASE64,
            r'^[A-Z2-7]+=*$': EncodingType.BASE32,
            r'^[0-9A-F]+$': EncodingType.HEX,
            r'%[0-9A-F]{2}': EncodingType.URL,
            r'&[a-zA-Z]+;': EncodingType.HTML,
            r'\\u[0-9A-F]{4}': EncodingType.UNICODE,
            r'^[01\s]+$': EncodingType.BINARY,
            r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$': EncodingType.JWT,
            r'^[A-Za-z]+$': EncodingType.ROT13,  # Simple heuristic
        }
    
    def _decode_base64(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode Base64"""
        try:
            # Remove padding if needed
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(data).decode('utf-8')
            
            # Calculate confidence based on valid UTF-8 and printable characters
            confidence = self._calculate_confidence(decoded)
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'padding_added': missing_padding > 0
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_base32(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode Base32"""
        try:
            decoded = base64.b32decode(data).decode('utf-8')
            confidence = self._calculate_confidence(decoded)
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded)
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_base16(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode Base16 (Hex)"""
        try:
            decoded = base64.b16decode(data).decode('utf-8')
            confidence = self._calculate_confidence(decoded)
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded)
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_url(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode URL encoding"""
        try:
            decoded = urllib.parse.unquote(data)
            confidence = 1.0 if decoded != data else 0.0
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'encoded_characters': len([c for c in data if c == '%'])
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_html(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode HTML entities"""
        try:
            decoded = html.unescape(data)
            confidence = 1.0 if decoded != data else 0.0
            
            # Count HTML entities
            entity_count = len(re.findall(r'&[a-zA-Z]+;|&#\d+;|&#x[0-9A-Fa-f]+;', data))
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'html_entities_found': entity_count
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_hex(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode hexadecimal"""
        try:
            # Remove spaces and common prefixes
            clean_data = re.sub(r'[^0-9A-Fa-f]', '', data)
            
            if len(clean_data) % 2 != 0:
                return "", False, 0.0, {'error': 'Invalid hex length'}
            
            decoded = bytes.fromhex(clean_data).decode('utf-8')
            confidence = self._calculate_confidence(decoded)
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'hex_pairs': len(clean_data) // 2
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_binary(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode binary string"""
        try:
            # Remove spaces and convert to bytes
            binary_string = re.sub(r'[^01]', '', data)
            
            if len(binary_string) % 8 != 0:
                return "", False, 0.0, {'error': 'Invalid binary length'}
            
            # Convert binary to bytes
            bytes_data = bytes(int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8))
            decoded = bytes_data.decode('utf-8')
            confidence = self._calculate_confidence(decoded)
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'binary_bits': len(binary_string)
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_gzip(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode GZIP compressed data"""
        try:
            # Try to decode as base64 first
            try:
                compressed_data = base64.b64decode(data)
            except:
                compressed_data = data.encode()
            
            decoded = gzip.decompress(compressed_data).decode('utf-8')
            confidence = self._calculate_confidence(decoded)
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'compression_ratio': len(compressed_data) / len(decoded) if len(decoded) > 0 else 0
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_zlib(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode ZLIB compressed data"""
        try:
            # Try to decode as base64 first
            try:
                compressed_data = base64.b64decode(data)
            except:
                compressed_data = data.encode()
            
            decoded = zlib.decompress(compressed_data).decode('utf-8')
            confidence = self._calculate_confidence(decoded)
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'compression_ratio': len(compressed_data) / len(decoded) if len(decoded) > 0 else 0
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_jwt(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode JWT token"""
        try:
            # Decode JWT without verification
            decoded = jwt.decode(data, options={"verify_signature": False})
            
            # Format as JSON
            formatted = json.dumps(decoded, indent=2)
            confidence = 1.0
            
            # Extract header and payload
            parts = data.split('.')
            header = json.loads(base64.b64decode(parts[0] + '==').decode())
            payload = json.loads(base64.b64decode(parts[1] + '==').decode())
            
            metadata = {
                'header': header,
                'payload': payload,
                'algorithm': header.get('alg', 'unknown'),
                'expires': payload.get('exp'),
                'issued_at': payload.get('iat')
            }
            
            return formatted, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_unicode(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode Unicode escape sequences"""
        try:
            decoded = data.encode().decode('unicode_escape')
            confidence = 1.0 if '\\u' in data else 0.0
            
            # Count unicode sequences
            unicode_count = len(re.findall(r'\\u[0-9A-Fa-f]{4}', data))
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'unicode_sequences': unicode_count
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_rot13(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode ROT13"""
        try:
            decoded = self._encode_rot13(data)  # ROT13 is symmetric
            confidence = 0.5  # ROT13 is always possible
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded)
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_caesar(self, data: str, shift: int = 3) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode Caesar cipher"""
        try:
            decoded = self._encode_caesar(data, -shift)  # Decode by shifting back
            confidence = 0.3  # Low confidence as shift is unknown
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'shift_used': shift
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_reverse(self, data: str) -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode reversed string"""
        try:
            decoded = data[::-1]
            confidence = 0.5  # Always possible but low confidence
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded)
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _decode_xor(self, data: str, key: str = "key") -> Tuple[str, bool, float, Dict[str, Any]]:
        """Decode XOR cipher"""
        try:
            # Try to decode as hex first
            try:
                hex_data = bytes.fromhex(data)
            except:
                hex_data = data.encode()
            
            # XOR with key
            decoded_bytes = bytes(a ^ b for a, b in zip(hex_data, (key * (len(hex_data) // len(key) + 1)).encode()))
            decoded = decoded_bytes.decode('utf-8')
            confidence = self._calculate_confidence(decoded)
            
            metadata = {
                'original_length': len(data),
                'decoded_length': len(decoded),
                'key_used': key
            }
            
            return decoded, True, confidence, metadata
            
        except Exception as e:
            return "", False, 0.0, {'error': str(e)}
    
    def _encode_rot13(self, data: str) -> str:
        """Encode ROT13"""
        result = ""
        for char in data:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result
    
    def _encode_caesar(self, data: str, shift: int) -> str:
        """Encode Caesar cipher"""
        result = ""
        for char in data:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                result += char
        return result
    
    def _calculate_confidence(self, decoded: str) -> float:
        """Calculate confidence in decoded result"""
        if not decoded:
            return 0.0
        
        # Check for printable ASCII characters
        printable_chars = sum(1 for c in decoded if 32 <= ord(c) <= 126)
        printable_ratio = printable_chars / len(decoded)
        
        # Check for common patterns
        pattern_score = 0.0
        if re.search(r'[a-zA-Z]{3,}', decoded):  # Words
            pattern_score += 0.2
        if re.search(r'\d+', decoded):  # Numbers
            pattern_score += 0.1
        if re.search(r'[!@#$%^&*()_+=\[\]{}|;:,.<>?]', decoded):  # Symbols
            pattern_score += 0.1
        
        confidence = (printable_ratio * 0.7) + (pattern_score * 0.3)
        return min(confidence, 1.0)
    
    def get_decode_history(self) -> List[DecodeResult]:
        """Get decode history"""
        return self.decode_history
    
    def clear_history(self):
        """Clear decode history"""
        self.decode_history = []
        self.logger.info("[*] Decode history cleared")
    
    def export_results(self, filename: str):
        """Export decode results to file"""
        try:
            import json
            
            export_data = {
                'decode_history': [result.__dict__ for result in self.decode_history],
                'total_decodes': len(self.decode_history),
                'successful_decodes': len([r for r in self.decode_history if r.success])
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.success(f"[+] Decode results exported to {filename}")
            
        except Exception as e:
            self.logger.error(f"[-] Export failed: {e}")
