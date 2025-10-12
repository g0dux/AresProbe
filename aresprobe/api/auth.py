"""
AresProbe API Authentication
JWT authentication and API key management
"""

import jwt
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from dataclasses import dataclass
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext

from ..core.logger import Logger

@dataclass
class User:
    """User data structure"""
    id: str
    username: str
    email: str
    role: str
    api_keys: List[str]
    created_at: datetime
    last_login: Optional[datetime]
    is_active: bool

@dataclass
class APIKey:
    """API Key data structure"""
    key: str
    name: str
    user_id: str
    permissions: List[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    is_active: bool

class AuthManager:
    """Authentication and authorization manager"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.secret_key = self._generate_secret_key()
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
        self.refresh_token_expire_days = 7
        
        # Password hashing
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # In-memory storage (in production, use database)
        self.users: Dict[str, User] = {}
        self.api_keys: Dict[str, APIKey] = {}
        self.sessions: Dict[str, Dict] = {}
        
        # Initialize default admin user
        self._create_default_admin()
    
    def _generate_secret_key(self) -> str:
        """Generate secret key for JWT"""
        return secrets.token_urlsafe(32)
    
    def _create_default_admin(self):
        """Create default admin user"""
        admin_id = "admin"
        admin_user = User(
            id=admin_id,
            username="admin",
            email="admin@aresprobe.com",
            role="admin",
            api_keys=[],
            created_at=datetime.utcnow(),
            last_login=None,
            is_active=True
        )
        
        # Create default API key
        api_key = self._generate_api_key()
        admin_user.api_keys.append(api_key)
        
        api_key_obj = APIKey(
            key=api_key,
            name="Default Admin Key",
            user_id=admin_id,
            permissions=["*"],  # All permissions
            created_at=datetime.utcnow(),
            expires_at=None,  # Never expires
            last_used=None,
            is_active=True
        )
        
        self.users[admin_id] = admin_user
        self.api_keys[api_key] = api_key_obj
        
        self.logger.info(f"[+] Default admin user created with API key: {api_key[:8]}...")
    
    def _generate_api_key(self) -> str:
        """Generate new API key"""
        return f"ares_{secrets.token_urlsafe(32)}"
    
    def hash_password(self, password: str) -> str:
        """Hash password"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def create_access_token(self, data: Dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(self, data: Dict) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Dict:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        # For demo purposes, using simple authentication
        # In production, verify against database
        if username == "admin" and password == "admin":
            user = self.users.get("admin")
            if user and user.is_active:
                user.last_login = datetime.utcnow()
                return user
        return None
    
    def authenticate_api_key(self, api_key: str) -> Optional[User]:
        """Authenticate user with API key"""
        key_obj = self.api_keys.get(api_key)
        if not key_obj or not key_obj.is_active:
            return None
        
        # Check expiration
        if key_obj.expires_at and datetime.utcnow() > key_obj.expires_at:
            return None
        
        # Update last used
        key_obj.last_used = datetime.utcnow()
        
        # Return user
        user = self.users.get(key_obj.user_id)
        if user and user.is_active:
            return user
        
        return None
    
    def check_permission(self, user: User, permission: str) -> bool:
        """Check if user has permission"""
        if user.role == "admin":
            return True
        
        # Check API key permissions
        for api_key in user.api_keys:
            key_obj = self.api_keys.get(api_key)
            if key_obj and key_obj.is_active:
                if "*" in key_obj.permissions or permission in key_obj.permissions:
                    return True
        
        return False
    
    def create_user(self, username: str, email: str, password: str, role: str = "user") -> User:
        """Create new user"""
        user_id = secrets.token_urlsafe(16)
        
        user = User(
            id=user_id,
            username=username,
            email=email,
            role=role,
            api_keys=[],
            created_at=datetime.utcnow(),
            last_login=None,
            is_active=True
        )
        
        self.users[user_id] = user
        self.logger.info(f"[+] User created: {username}")
        return user
    
    def create_api_key(self, user_id: str, name: str, permissions: List[str], expires_days: Optional[int] = None) -> APIKey:
        """Create new API key for user"""
        user = self.users.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        api_key = self._generate_api_key()
        
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        api_key_obj = APIKey(
            key=api_key,
            name=name,
            user_id=user_id,
            permissions=permissions,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            last_used=None,
            is_active=True
        )
        
        self.api_keys[api_key] = api_key_obj
        user.api_keys.append(api_key)
        
        self.logger.info(f"[+] API key created for user {user.username}: {name}")
        return api_key_obj
    
    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke API key"""
        key_obj = self.api_keys.get(api_key)
        if key_obj:
            key_obj.is_active = False
            self.logger.info(f"[+] API key revoked: {key_obj.name}")
            return True
        return False
    
    def get_user_stats(self) -> Dict:
        """Get user statistics"""
        total_users = len(self.users)
        active_users = len([u for u in self.users.values() if u.is_active])
        total_api_keys = len(self.api_keys)
        active_api_keys = len([k for k in self.api_keys.values() if k.is_active])
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "total_api_keys": total_api_keys,
            "active_api_keys": active_api_keys,
            "recent_logins": len([u for u in self.users.values() 
                                if u.last_login and (datetime.utcnow() - u.last_login).days < 7])
        }

# FastAPI dependencies
security = HTTPBearer()

def get_auth_manager() -> AuthManager:
    """Get auth manager instance"""
    from ..core.logger import Logger
    return AuthManager(Logger())

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Get current authenticated user"""
    auth_manager = get_auth_manager()
    
    # Try API key authentication first
    if credentials.credentials.startswith("ares_"):
        user = auth_manager.authenticate_api_key(credentials.credentials)
        if user:
            return user
    
    # Try JWT authentication
    try:
        payload = auth_manager.verify_token(credentials.credentials)
        user_id = payload.get("sub")
        user = auth_manager.users.get(user_id)
        if user and user.is_active:
            return user
    except:
        pass
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials"
    )

def require_permission(permission: str):
    """Require specific permission"""
    def permission_checker(current_user: User = Depends(get_current_user)):
        auth_manager = get_auth_manager()
        if not auth_manager.check_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return permission_checker

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user
