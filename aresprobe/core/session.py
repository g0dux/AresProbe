"""
AresProbe Session Manager
Manages user sessions and authentication state
"""

import json
import time
import hashlib
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

from .logger import Logger


@dataclass
class SessionData:
    """Session data structure"""
    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    is_active: bool
    metadata: Dict[str, Any]


class SessionManager:
    """
    Manages user sessions and authentication state
    """
    
    def __init__(self):
        self.logger = Logger()
        self.sessions: Dict[str, SessionData] = {}
        self.session_timeout = 3600  # 1 hour
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()
    
    def initialize(self):
        """Initialize session manager"""
        self.logger.info("[*] Initializing session manager...")
        self._start_cleanup_thread()
        self.logger.success("[+] Session manager initialized")
    
    def create_session(self, user_id: str, metadata: Dict[str, Any] = None) -> str:
        """Create a new session"""
        session_id = self._generate_session_id()
        now = datetime.now()
        
        session_data = SessionData(
            session_id=session_id,
            user_id=user_id,
            created_at=now,
            last_activity=now,
            is_active=True,
            metadata=metadata or {}
        )
        
        self.sessions[session_id] = session_data
        self.logger.info(f"[*] Created session {session_id} for user {user_id}")
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get session data by ID"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            if self._is_session_valid(session):
                session.last_activity = datetime.now()
                return session
            else:
                self._invalidate_session(session_id)
        
        return None
    
    def update_session(self, session_id: str, metadata: Dict[str, Any]):
        """Update session metadata"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            if self._is_session_valid(session):
                session.metadata.update(metadata)
                session.last_activity = datetime.now()
                self.logger.info(f"[*] Updated session {session_id}")
            else:
                self._invalidate_session(session_id)
    
    def invalidate_session(self, session_id: str):
        """Invalidate a session"""
        self._invalidate_session(session_id)
    
    def _invalidate_session(self, session_id: str):
        """Internal method to invalidate session"""
        if session_id in self.sessions:
            self.sessions[session_id].is_active = False
            del self.sessions[session_id]
            self.logger.info(f"[*] Invalidated session {session_id}")
    
    def _is_session_valid(self, session: SessionData) -> bool:
        """Check if session is valid and not expired"""
        if not session.is_active:
            return False
        
        time_diff = (datetime.now() - session.last_activity).total_seconds()
        return time_diff < self.session_timeout
    
    def _generate_session_id(self) -> str:
        """Generate a unique session ID"""
        timestamp = str(time.time())
        random_data = str(hash(timestamp))
        session_string = f"{timestamp}_{random_data}"
        return hashlib.sha256(session_string.encode()).hexdigest()[:32]
    
    def _start_cleanup_thread(self):
        """Start cleanup thread for expired sessions"""
        import threading
        
        def cleanup_loop():
            while True:
                try:
                    time.sleep(self.cleanup_interval)
                    self._cleanup_expired_sessions()
                except Exception as e:
                    self.logger.error(f"[-] Session cleanup error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval:
            return
        
        expired_sessions = []
        for session_id, session in self.sessions.items():
            if not self._is_session_valid(session):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self._invalidate_session(session_id)
        
        if expired_sessions:
            self.logger.info(f"[*] Cleaned up {len(expired_sessions)} expired sessions")
        
        self.last_cleanup = now
    
    def get_active_sessions(self) -> Dict[str, SessionData]:
        """Get all active sessions"""
        active_sessions = {}
        for session_id, session in self.sessions.items():
            if self._is_session_valid(session):
                active_sessions[session_id] = session
        
        return active_sessions
    
    def get_session_count(self) -> int:
        """Get total number of active sessions"""
        return len(self.get_active_sessions())
    
    def cleanup(self):
        """Cleanup all sessions"""
        self.logger.info("[*] Cleaning up all sessions...")
        self.sessions.clear()
        self.logger.success("[+] Session cleanup completed")
