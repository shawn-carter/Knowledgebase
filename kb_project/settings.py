"""
Django settings for myknowledgebase project.

Generated by 'django-admin startproject' using Django 4.2.4.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY', '65#oxwiww2y6aeaiadi&#s9va!5puhqkx=6a(1p1u#*%($!#5=')

ALLOWED_HOSTS = ['shawncarter.pythonanywhere.com','127.0.0.1','azure.shwan.tech','knowledgebase-devenv.azurewebsites.net']

CSRF_TRUSTED_ORIGINS = [
    'https://azure.shwan.tech',
    # Add any other domain variations if necessary
]

# Application definition

INSTALLED_APPS = [
    'kb_app',
    'mssql',
    'corsheaders',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'widget_tweaks',
    'django_extensions',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'kb_app.middleware.csp_nonce_middleware.CSPNonceMiddleware',
    'csp.middleware.CSPMiddleware',
]

ROOT_URLCONF = 'kb_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'kb_project.wsgi.application'

# Content Security Policy (CSP)
CSP_DEFAULT_SRC = ("'self'", )
CSP_SCRIPT_SRC = (
    "'self'","'nonce-{}'"
    'https://cdn.datatables.net', 
    'https://cdn.jsdelivr.net', 
    'https://cdn.quilljs.com', 
    'https://code.jquery.com',
    "'sha256-aqNNdDLnnrDOnTNdkJpYlAxKVJtLt9CtFLklmInuUAE='",
    "'sha256-BVHXCPA4OFXCfWS+ZsY5hIuf3D8+7LFZGKL5IRkmHFU='",
    "'sha256-BlytFmIIb51t6hGjjd9/VhTerovSuN7JfGMToS0WfYQ='",
    "'sha256-CdPEdf7NiQ6K295E0TLwoOcryfqgXeFlzOYyBpX67Ig='",
    "'sha256-dn/d/mxDWHH7jwOB+nxnivi9k+pO//eoyYHCjBYKc/A='",
    # ... (any other script sources you need) ...
)
CSP_STYLE_SRC = (
    "'self'",
    'https://cdn.datatables.net', 
    'https://cdn.jsdelivr.net',
    'https://cdn.quilljs.com',
    "'sha256-aqNNdDLnnrDOnTNdkJpYlAxKVJtLt9CtFLklmInuUAE='",
    "'sha256-r06yVUBqP+7ZbDWovXc9AqepL8NwsS69BQIUpScMDvU='",
    "'sha256-0EZqoz+oBhx7gF4nvY2bSqoGyy4zLjNF+SDQXGp/ZrY='",
    "'sha256-RvAvREUHojDuwHylTVWZp9DhleqLs6ml8G7LpjCF+EY='",
    "'sha256-ZdHxw9eWtnxUb3mk6tBS+gIiVUPE3pGM470keHPDFlE='",
         
    # ... (any other style sources you need) ...
)
CSP_IMG_SRC = (
    "'self'",
    'https://cdn.jsdelivr.net',
    'http://www.w3.org/2000/svg',
    # ... (any other image sources you need) ...
)


# Check if running in Azure environment
if os.environ.get('ENVIRONMENT') == 'PRODUCTION':
    
    # Turn off Debug in Production Environment
    DEBUG = False
    
    # Secure settings for production in Azure
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SESSION_EXPIRE_AT_BROWSER_CLOSE = True
    
    # Cross Origin Resource Sharing Policy
    CORS_ALLOWED_ORIGINS = [
    "http://127.0.0.1:8000",
    "https://azure.shwan.tech"
    # ... other domains ...
    ]
    
    # Database (using Environment variables)
    # https://docs.djangoproject.com/en/4.2/ref/settings/#databases
    DATABASES = {
        'default': {
            'ENGINE': 'mssql',
            'NAME': os.environ['AZURE_SQL_DATABASE'],
            'USER': os.environ['AZURE_SQL_USER'],
            'PASSWORD': os.environ['AZURE_SQL_PASSWORD'],
            'HOST': os.environ['AZURE_SQL_SERVER'],
            'PORT': os.environ['AZURE_SQL_PORT'],
            'OPTIONS': {
                'driver': 'ODBC Driver 17 for SQL Server',
            },
        }
    }
    
else:
    # SECURITY WARNING: don't run with debug turned on in production!
    DEBUG = True
    
    # Use the local sqllite DB
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
        }
    }


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Europe/London'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]  # Update if you have app-specific static files

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGIN_URL='login'

GRAPH_MODELS ={
'all_applications': True,
'graph_models': True,
}