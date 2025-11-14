# backend/settings.py

from pathlib import Path
import environ
import os
from datetime import timedelta

# --- Environment Variable Setup ---
env = environ.Env(
    DEBUG=(bool, False)
)

BASE_DIR = Path(__file__).resolve().parent.parent
environ.Env.read_env(BASE_DIR / '.env')


# --- Core Django Settings ---
SECRET_KEY = env('DJANGO_SECRET_KEY', default='django-insecure-default-key-for-dev') # Added default for safety
DEBUG = env('DEBUG')
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
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

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
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR.parent / 'sva_database' / 'db.sqlite3',
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

# --- Static files ---
STATIC_URL = 'static/'
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
# Use local development URL when DEBUG is True, otherwise use production URL
if DEBUG:
    SVA_AUTH_SERVER_BASE_URL = env('SVA_AUTH_SERVER_BASE_URL', default='http://localhost:8001')
else:
    SVA_AUTH_SERVER_BASE_URL = env('SVA_AUTH_SERVER_BASE_URL', default='http://sva-auth-server:8000')
# DATA_TOKEN_SECRET must match sva_oauth backend - use same default for local development
DATA_TOKEN_SECRET = env('DATA_TOKEN_SECRET', default='dev-data-token-secret')
DATA_TOKEN_ALGORITHM = env('DATA_TOKEN_ALGORITHM', default='HS256')
DATA_TOKEN_TTL_SECONDS = env.int('DATA_TOKEN_TTL_SECONDS', default=300)
DATA_TOKEN_ISSUER = env('DATA_TOKEN_ISSUER', default='sva_core')
INTERNAL_SERVICE_TIMEOUT = env.int('INTERNAL_SERVICE_TIMEOUT', default=5)


# --- Email Settings for Password Reset ---
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend' # For production
# EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend' # For testing in console
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
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