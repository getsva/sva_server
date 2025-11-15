# backend/settings.py
"""
Django settings for SVA Server project.

Environment Configuration:
---------------------------
This settings file automatically configures itself based on the ENVIRONMENT variable.
You can use separate .env files for different environments:

1. For Local Development:
   - Use .env.local file
   - Or set ENVIRONMENT=development system environment variable
   - DEBUG will be automatically set to True
   - Console email backend will be used
   - Less strict security settings

2. For Production:
   - Use .env.production file
   - Or set ENVIRONMENT=production system environment variable
   - DEBUG will be automatically set to False (security requirement)
   - SMTP email backend will be used
   - Production security settings will be enabled (HTTPS, secure cookies, etc.)

File Loading Priority:
- System environment variable ENVIRONMENT takes precedence
- Then loads .env.local (development) or .env.production (production)
- Falls back to .env if environment-specific file doesn't exist

All environment variables should be defined in the appropriate .env file.
"""

from pathlib import Path
import environ
import os
from datetime import timedelta
import dj_database_url

# --- Environment Variable Setup ---
env = environ.Env(
    DEBUG=(bool, False),
    ENVIRONMENT=(str, 'development')
)

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Environment Detection ---
# First, try to get ENVIRONMENT from system environment variable (for deployment platforms)
# Then try to read from .env file, then from environment-specific files
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development').lower()

# Load environment-specific .env file
# Priority: .env.local (development) or .env.production (production)
# Fallback to .env if environment-specific file doesn't exist
if ENVIRONMENT == 'production':
    env_file = BASE_DIR / '.env.production'
    if not env_file.exists():
        # Fallback to .env if .env.production doesn't exist
        env_file = BASE_DIR / '.env'
else:
    # Development environment
    env_file = BASE_DIR / '.env.local'
    if not env_file.exists():
        # Fallback to .env if .env.local doesn't exist
        env_file = BASE_DIR / '.env'

# Read the appropriate .env file
if env_file.exists():
    environ.Env.read_env(env_file)
    # Re-read ENVIRONMENT from the loaded file (it may override the system env)
    ENVIRONMENT = env('ENVIRONMENT', default=ENVIRONMENT).lower()

IS_PRODUCTION = ENVIRONMENT == 'production'
IS_DEVELOPMENT = ENVIRONMENT == 'development'

# --- Core Django Settings ---
SECRET_KEY = env('DJANGO_SECRET_KEY', default='django-insecure-default-key-for-dev') # Added default for safety

# Auto-configure DEBUG based on environment if not explicitly set
# In production, DEBUG should always be False for security
if 'DEBUG' in os.environ:
    DEBUG = env('DEBUG')
else:
    DEBUG = IS_DEVELOPMENT  # Auto-set based on environment

# Ensure DEBUG is False in production (security requirement)
if IS_PRODUCTION:
    DEBUG = False

# ALLOWED_HOSTS - must include your Azure App Service domain
# For Azure App Service, you MUST set this in environment variables:
# ALLOWED_HOSTS=sva-server.azurewebsites.net,api.getsva.com
# Or set it in Azure Portal > Configuration > Application Settings
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['127.0.0.1', 'localhost'])

# --- Application Definitions ---
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # 3rd Party Apps
    'rest_framework',
    'corsheaders',

    # Local Apps
    'authentication',
    'svasetting',
    'identity_canvas',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Serve static files efficiently in production
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'backend.middleware.HealthCheckCommonMiddleware',  # Custom middleware to prevent redirect loops
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# --- Security Settings (Production) ---
if IS_PRODUCTION:
    # CRITICAL: Tell Django to trust Azure App Service's reverse proxy headers
    # Azure App Service sits behind a reverse proxy, and Django needs to know
    # that requests are already HTTPS by checking the X-Forwarded-Proto header.
    # Without this, SECURE_SSL_REDIRECT will cause infinite redirect loops.
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    
    # Security settings for production
    SECURE_SSL_REDIRECT = env('SECURE_SSL_REDIRECT', default=True, cast=bool)
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

# --- Database ---
# Use a default SQLite database if DATABASE_URL is not set (useful for collectstatic, migrations, etc.)
# In production, DATABASE_URL should always be set
database_url = env('DATABASE_URL', default='')
if database_url:
    DATABASES = {
        'default': dj_database_url.config(
            default=database_url,
            conn_max_age=600,
            ssl_require=env('DB_SSL_REQUIRE', default=False, cast=bool)
        )
    }
else:
    # Fallback to SQLite for development or when DATABASE_URL is not set (e.g., during collectstatic)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# --- Password Validation ---
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# --- Internationalization ---
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# --- URL Configuration ---
# Disable APPEND_SLASH for root health check endpoint to prevent redirect loops
# on Azure App Service and other platforms
APPEND_SLASH = True  # Keep enabled for other endpoints, but root path handles both

# --- Static files ---
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# WhiteNoise configuration for serving static files in production
# WhiteNoise allows your Django app to serve its own static files efficiently
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# --- CORS Settings ---
CORS_ALLOWED_ORIGINS = env.list(
    'CORS_ALLOWED_ORIGINS',
    default=['http://localhost:8080', 'http://127.0.0.1:8080']
)
CORS_ALLOW_CREDENTIALS = True


# --- Django REST Framework Settings ---
# We now point to our custom authentication class
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'authentication.custom_auth.CustomTokenAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

# --- Custom Token Settings ---
# We define our token lifetimes here for easy access
ACCESS_TOKEN_LIFETIME = timedelta(days=7)
REFRESH_TOKEN_LIFETIME = timedelta(days=7)


# --- Internal Service-to-Service Communication ---
INTERNAL_SERVICE_TOKEN = env('INTERNAL_SERVICE_TOKEN', default='dev-shared-secret')
INTERNAL_SERVICE_HEADER = env('INTERNAL_SERVICE_HEADER', default='X-Service-Token')

# Configure auth server URL based on environment
if IS_DEVELOPMENT:
    SVA_AUTH_SERVER_BASE_URL = env('SVA_AUTH_SERVER_BASE_URL', default='http://localhost:8001')
else:
    # Production: use environment variable or default production URL
    SVA_AUTH_SERVER_BASE_URL = env('SVA_AUTH_SERVER_BASE_URL', default='http://sva-auth-server:8000')
# DATA_TOKEN_SECRET must match sva_oauth backend - use same default for local development
DATA_TOKEN_SECRET = env('DATA_TOKEN_SECRET', default='dev-data-token-secret')
DATA_TOKEN_ALGORITHM = env('DATA_TOKEN_ALGORITHM', default='HS256')
DATA_TOKEN_TTL_SECONDS = env.int('DATA_TOKEN_TTL_SECONDS', default=300)
DATA_TOKEN_ISSUER = env('DATA_TOKEN_ISSUER', default='sva_core')
INTERNAL_SERVICE_TIMEOUT = env.int('INTERNAL_SERVICE_TIMEOUT', default=5)


# --- Email Settings for Password Reset ---
# Auto-configure email backend based on environment
EMAIL_BACKEND_TYPE = env('EMAIL_BACKEND', default='smtp' if IS_PRODUCTION else 'console').lower()

if EMAIL_BACKEND_TYPE == 'console' or (IS_DEVELOPMENT and EMAIL_BACKEND_TYPE != 'smtp'):
    # Use console backend for development/testing
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
else:
    # Use SMTP backend for production
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = env('EMAIL_HOST', default='smtp.gmail.com')
    EMAIL_PORT = env.int('EMAIL_PORT', default=587)
    EMAIL_USE_TLS = env('EMAIL_USE_TLS', default=True, cast=bool)
    EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='your-email@gmail.com')
    EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD', default='your-app-password')
    DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default='no-reply@yourdomain.com')

# --- Zero-Knowledge Pepper Constants (for k-anonymity uniqueness checks) ---
# Public pepper is known to clients and used for initial hashing
# Secret pepper is server-only and used for final proof generation
SVA_PUBLIC_PEPPER = env(
    'SVA_PUBLIC_PEPPER',
    default='sva-public-pepper-2024-zero-knowledge-uniqueness-check'
)
SVA_SECRET_SERVER_PEPPER = env(
    'SVA_SECRET_SERVER_PEPPER',
    default='sva-secret-server-pepper-2024-never-expose-this-value'
)