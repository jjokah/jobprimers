from typing import ClassVar

from datetime import datetime, timedelta
from django.contrib.auth.models import AbstractUser
from django.db.models import CharField, Model, CASCADE
from django.db.models import EmailField, BooleanField, DateTimeField, PositiveIntegerField, Index, ImageField, TextField, GenericIPAddressField, ForeignKey, UUIDField
from django.urls import reverse
from django.conf import settings
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
import jwt
import uuid
import secrets
import hashlib

from .managers import UserManager


class CustomUserManager(UserManager):
    """Custom user manager for creating job_seekers(users), recruiters and admin"""
    
    def create_user(self, email, password, **extra_fields):
        """Create and return the regular user."""
        if not email:
            raise ValueError('The email field must be set.')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_recruiter(self, email, password, **extra_fields):
        """Create and return a recruiter."""
        extra_fields.setdefault('role', 'recruiter')
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('role') is not 'recruiter':
            raise ValueError('Recruiter must have role recruiter')
        
        return self.create_user(email, password, **extra_fields)
    
    def create_adminuser(self, email, password, **extra_fields):
        """Create and return an adminuser."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'admin')

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Admin  must have is_staff=True")
        
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Admin must have is_superuser=True')
        
        return self.create_user(email, password, **extra_fields)
        

class User(AbstractUser):
    """
    Default custom user model for Jobprimers.
    If adding fields that need to be filled at user signup,
    check forms.SignupForm and forms.SocialSignupForms accordingly.
    """
# Role choices
    ROLE_CHOICES = [
        ('user', 'User'),
        ('admin', 'Admin'),
        ('recruiter', 'Recruiter'),
    ]

    # First and last name do not cover name patterns around the globe
    name = CharField(_("Name of User"), blank=True, max_length=255)
    first_name = None  # type: ignore[assignment]
    last_name = None  # type: ignore[assignment]
    email = EmailField(_("email address"), unique=True)
    username = None  # type: ignore[assignment]
    phone_number = CharField(_("User Phone Number"), blank=True, max_length=15, validators=[RegexValidator(
            regex=r'^\+?[\d\s\-\(\)]+$',
            message='Please enter a valid phone number'
        )])

    # Role and permissions
    role = CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='user'
    )

     # Email verification
    is_email_verified = BooleanField(default=False)
    email_verification_token = CharField(max_length=255, blank=True)
    email_verification_expires = DateTimeField(blank=True, null=True)

    # Password reset
    password_reset_token = CharField(max_length=255, blank=True)
    password_reset_expires = DateTimeField(blank=True, null=True)

    # Account security
    is_locked = BooleanField(default=False)
    lock_until = DateTimeField(blank=True, null=True)
    login_attempts = PositiveIntegerField(default=0)
    
    # Metadata
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)

    # Login tracking
    last_login_ip = GenericIPAddressField(blank=True, null=True)
    last_login_user_agent = TextField(blank=True)
    password_changed_at = DateTimeField(auto_now_add=True)


    # Profile settings
    avatar = ImageField(
        upload_to='avatars/',
        blank=True,
        null=True
    )
 
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    objects: ClassVar[UserManager] = UserManager()

    class Meta:
        indexes = [
            Index(fields=['email']),
            Index(fields=['username']),
            Index(fields=['created_at']),
            Index(fields=['last_login'])
        ]

    @property
    def full_name(self):
        """Return the user's full name."""
        return f"{self.first_name} {self.last_name}".strip()
    
    @property
    def is_account_locked(self):
        """Check if the accoutn is currently locked."""
        return self.is_locked and self.lock_until and self.lock_until > self.lock_until > datetime.now()
    
    def set_password(self, raw_password):
        """Override set_password to update password_changed_at timestamp."""
        super().set_password(raw_password)
        self.password_changed_at = datetime.now()

    def generate_auth_token(self, expires_delta=None):
        """Generate a JWT authentication token."""
        if expires_delta is None:
            expires_delta = timedelta(minutes=15)

        payload = {
            'user_id': self.id,
            'email': self.email,
            'role': self.role,
            'exp': datetime.now() + expires_delta,
            'iat': datetime.now(),
            'type': 'access'
        }

        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    
    def generate_refresh_token(self, expires_delta=None):
        """Generate a JWT refresh token."""
        if expires_delta is None:
            expires_delta = timedelta(days=7)

        payload ={
            'user_id': self.id,
            'exp': datetime.now() +expires_delta,
            'iat': datetime.now(),
            'type': 'refresh',
            'jti': str(uuid.uuid4())
        }

        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    
    def generate_email_verification_token(self):
        """Generate an email verification token."""
        token = secrets.token_urlsafe(32)

        # Hash the token and then store it
        self.email_verification_token = hashlib.sha256(token.encode()).hexdigest()

        self.email_verification_expires = datetime.now() + timedelta(hours=24)

        self.save(update_fields=['email_verification_token', 'email_verification_expires'])

        return token
    
    def generate_password_reset_token(self):
        """Generate a password reset token."""
        token = secrets.token_urlsafe(32)

        # Hash the tokne and then store it
        self.password_reset_token = hashlib.sha256(token.encode()).hexdigest()

        self.password_reset_expires = datetime.now() + timedelta(minutes=15)
        self.save(update_fields=['password_reset_token', 'password_reset_expires'])

        return token
    
    def verify_email_token(self, token):
        """Verify an email verification token."""
        if not self.email_verification_token or not self.email_verification_expires:
            return False
        
        if datetime.now() > self.email_verification_expires:
            return False
        
        hashed_token = hashlib.sha256(token.encode()).hexdigest()
        return self.email_verification_token == hashed_token
    
    def verify_password_reset_token(self, token):
        """Verify a password reset token."""
        if not self.password_reset_token or not self.password_reset_expires:
            return False
        
        if datetime.now() > self.password_reset_expires:
            return False
        
        hashed_token = hashlib.sha256(token.encode()).hexdigest()
        return self.password_reset_token == hashed_token
    
    def handle_failed_login(self):
        """Handle failed login attempt."""
        self.login_attempts +=1

        # Lock account after 5 failed attempts
        if self.login_attempts >= 5:
            self.is_locked = True
            self.lock_until = datetime.now() + timedelta(minutes=30)

        self.save(update_fields=['login_attempts', 'is_locked', 'lock_until'])

    def handle_successful_login(self, ip_address=None, user_agent=None):
        """Handle successful login."""
        self.login_attempts = 0
        self.is_locked = False
        self.lock_until = None
        self.last_login_ip = ip_address
        self.last_login_user_agent = user_agent
        self.last_login = datetime.now()

        self.save(update_fields=[
            'login_attempts', 'is_locked', 'lock_until',
            'last_login_ip', 'last_login_user_agent', 'last_login'
        ])

    def clear_verification_tokens(self):
        """Clear email verification tokens."""
        self.email_verification_token = ''
        self.email_verification_expires = None
        self.save(update_fields=['email_verification_token', 'email_verification_expires'])
    
    def clear_password_reset_tokens(self):
        """Clear password reset tokens."""
        self.password_reset_token = ''
        self.password_reset_expires = None
        self.save(update_fields=['password_reset_token', 'password_reset_expires'])

    @classmethod
    def find_by_email_verification_token(cls, token):
        """Find user by email verification token."""
        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        try:
            return cls.objects.get(email_verification_token=hashed_token, email_verification_expires__gt=datetime.now())
        except cls.DoesNotExist:
            return None
        
    @classmethod
    def find_by_password_reset_token(cls, token):
        """Find user by password reset token."""
        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        try:
            return cls.objects.get(password_reset_token=hashed_token, password_reset_expires__gt=datetime.now())

        except cls.DoesNotExist:
            return None
        
    @classmethod
    def cleanup_expired_token(cls):
        """Clean up expired tokens."""
        now = datetime.now()

        # Clear expired email verification tokens
        cls.objects.filter(
            email_verification_expires__lt=now
        ).update(
            email_verification_token="",
            email_verification_expires=None
        )

        # Clear expired password reset tokens
        cls.objects.filter(
            password_reset_expires__lt=now
        ).update(
            password_reset_token='',
            password_reset_expires=None
        )

    def get_absolute_url(self) -> str:
        """Get URL for user's detail view.

        Returns:
            str: URL for user detail.

        """
        return reverse("users:detail", kwargs={"pk": self.id})


class RefreshToken(Model):
    """Model to track refresh tokens for session management."""
    user = ForeignKey(
        User,
        on_delete=CASCADE,
        related_name='refresh_tokens'
    )
    token_id = UUIDField(unique=True)
    created_at = DateTimeField(auto_now_add=True)
    expires_at = DateTimeField()
    user_agent = TextField(blank=True)
    ip_address = GenericIPAddressField(blank=True, null=True)
    is_active = BooleanField(default=True)

    class Meta:
        indexes = [
            Index(fields=['user', 'is_active']),
            Index(fields=['token_id']),
            Index(fields=['expires_at'])
        ]

    def __str__(self):
        return f"RefreshToken for {self.user.email}"
    
    def is_expired(self):
        """Check if the token is expired."""
        return datetime.now() > self.expires_at
    
    def revoke(self):
        """Revoke this refresh token."""
        self.is_active = False
        self.save(update_fields=['is_active'])

    @classmethod
    def cleanup_expired(cls):
        """Remove expired refresh tokens."""
        cls.objects.filter(expires_at__lt=datetime.now()).delete()

    @classmethod
    def revoke_all_for_user(cls, user):
        """Revoke all refresh tokens for a user."""
        cls.objects.filter(user=user, is_active=True).update(is_active=False)

# Management command to run cleanup periodically
class Command:
    """
    Django management command to clean up expired tokens.
    Run with: python manage.py cleanup_tokens
    """

    help = 'Clean up expired authentication tokens'

    def handle(self, *args, **options):
        User.cleanup_expired_token()
        RefreshToken.cleanup_expired()
        

