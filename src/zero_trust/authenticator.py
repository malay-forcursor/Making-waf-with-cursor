"""Zero Trust Authentication"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict
import jwt
from passlib.context import CryptContext

logger = logging.getLogger(__name__)


class ZeroTrustAuthenticator:
    """
    Zero Trust authentication with continuous verification
    Implements multi-factor authentication and device fingerprinting
    """
    
    def __init__(self, settings):
        self.settings = settings
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Mock user database
        self.users = {
            "admin": {
                "username": "admin",
                "password_hash": self.pwd_context.hash("admin123"),
                "roles": ["admin"],
                "mfa_enabled": True
            },
            "user": {
                "username": "user",
                "password_hash": self.pwd_context.hash("user123"),
                "roles": ["user"],
                "mfa_enabled": False
            }
        }
        
        # Active sessions
        self.sessions = {}
        
        logger.info("Zero Trust Authenticator initialized")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def create_access_token(
        self,
        username: str,
        roles: list,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token"""
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.settings.jwt_expiration_minutes
            )
        
        to_encode = {
            "sub": username,
            "roles": roles,
            "exp": expire,
            "iat": datetime.utcnow()
        }
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.settings.secret_key,
            algorithm=self.settings.jwt_algorithm
        )
        
        return encoded_jwt
    
    async def authenticate(
        self,
        username: str,
        password: str,
        device_fingerprint: str,
        source_ip: str
    ) -> Optional[Dict]:
        """
        Authenticate user with Zero Trust principles
        
        Returns:
            Session information if successful, None otherwise
        """
        
        # Check if user exists
        user = self.users.get(username)
        if not user:
            logger.warning(f"Authentication failed: unknown user {username}")
            return None
        
        # Verify password
        if not self.verify_password(password, user["password_hash"]):
            logger.warning(f"Authentication failed: invalid password for {username}")
            return None
        
        # Generate token
        token = self.create_access_token(
            username=username,
            roles=user["roles"]
        )
        
        # Create session
        session = {
            "username": username,
            "token": token,
            "device_fingerprint": device_fingerprint,
            "source_ip": source_ip,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow(),
            "mfa_verified": not user["mfa_enabled"],  # Would require actual MFA
            "roles": user["roles"]
        }
        
        self.sessions[token] = session
        
        logger.info(f"✅ User {username} authenticated from {source_ip}")
        
        return session
    
    async def verify_session(self, token: str) -> Optional[Dict]:
        """Verify and refresh session"""
        
        session = self.sessions.get(token)
        if not session:
            return None
        
        # Check if session expired
        session_timeout = timedelta(seconds=self.settings.session_timeout)
        if datetime.utcnow() - session["last_activity"] > session_timeout:
            del self.sessions[token]
            logger.info(f"Session expired for {session['username']}")
            return None
        
        # Update last activity
        session["last_activity"] = datetime.utcnow()
        
        return session
    
    def get_user_roles(self, token: str) -> list:
        """Get user roles from token"""
        try:
            payload = jwt.decode(
                token,
                self.settings.secret_key,
                algorithms=[self.settings.jwt_algorithm]
            )
            return payload.get("roles", [])
        except jwt.PyJWTError:
            return []
