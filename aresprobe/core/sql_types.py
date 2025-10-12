"""
SQL Injection Types and Enums
Shared types to avoid circular imports
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Any


class SQLInjectionType(Enum):
    """Types of SQL injection techniques - ENHANCED BEYOND SQLMAP"""
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BASED = "time_based"
    UNION_BASED = "union_based"
    ERROR_BASED = "error_based"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"
    # ADVANCED TECHNIQUES SUPERIOR TO SQLMAP
    POLYMORPHIC = "polymorphic"
    AI_POWERED = "ai_powered"
    CONTEXT_AWARE = "context_aware"
    ADAPTIVE = "adaptive"
    MACHINE_LEARNING = "machine_learning"
    HONEYPOT_EVASION = "honeypot_evasion"
    MULTI_VECTOR = "multi_vector"
    ZERO_DAY = "zero_day"


class DatabaseType(Enum):
    """Supported database types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MARIADB = "mariadb"
    DB2 = "db2"
    INFORMIX = "informix"
    SYBASE = "sybase"
    TERADATA = "teradata"
    UNKNOWN = "unknown"


class WAFType(Enum):
    """WAF detection types"""
    CLOUDFLARE = "cloudflare"
    INCAPSULA = "incapsula"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"
    MODSECURITY = "modsecurity"
    F5_BIGIP = "f5_bigip"
    IMPERVA = "imperva"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    UNKNOWN = "unknown"


@dataclass
class InjectionContext:
    """Context information for injection attacks"""
    target_url: str
    parameter: str
    value: str
    database_type: DatabaseType
    waf_type: Optional[WAFType]
    detected_filters: List[str]
    response_patterns: Dict[str, Any]
    timing_baseline: float
    error_patterns: List[str]
    success_indicators: List[str]


@dataclass
class SQLPayload:
    """Enhanced SQL injection payload - SUPERIOR TO SQLMAP"""
    payload: str
    injection_type: SQLInjectionType
    description: str = ""
    risk_level: str = "medium"
    database_type: DatabaseType = DatabaseType.UNKNOWN
    waf_bypass: bool = False
    success_rate: float = 0.0
    success: bool = False
    response_time: float = 0.0
    error_message: str = ""
    extracted_data: str = ""
    confidence: float = 0.0
    evasion_technique: str = ""
    context_aware: bool = False
    polymorphic_variant: int = 0
    ai_generated: bool = False
    
    def __post_init__(self):
        """Initialize additional attributes"""
        if isinstance(self.injection_type, str):
            self.injection_type = SQLInjectionType(self.injection_type)
        if isinstance(self.database_type, str):
            self.database_type = DatabaseType(self.database_type)
