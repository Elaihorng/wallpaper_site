# wallpaper_site/settings.py
import os
from pathlib import Path
from dotenv import load_dotenv
import dj_database_url
import tempfile

# Load local .env for local dev (ignored in production)
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY
SECRET_KEY = os.getenv("DJANGO_SECRET", "dev-secret")
DEBUG = os.getenv("DEBUG", "False").lower() in ("1", "true", "yes")

ALLOWED_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "localhost").split(",") if h.strip()]

# Applications
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "wallpapers",
]

# Middleware (WhiteNoise added)
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "wallpaper_site.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "wallpapers" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "wallpaper_site.wsgi.application"

# Database: prefer DATABASE_URL (dj-database-url), else explicit MySQL vars
if os.getenv("DATABASE_URL"):
    DATABASES = {"default": dj_database_url.parse(os.getenv("DATABASE_URL"), conn_max_age=600)}
else:
    # If Aiven requires SSL CA, we can write it to a temp file and reference it below
    db_options = {}
    db_ssl_ca = os.getenv("DATABASE_SSL_CA")  # put raw CA PEM into this env var if needed
    if db_ssl_ca:
        ca_file = Path(tempfile.gettempdir()) / "aiven_mysql_ca.pem"
        ca_file.write_text(db_ssl_ca)
        db_options["ssl"] = {"ca": str(ca_file)}

   

    if os.getenv("DATABASE_URL"):
        # parse DATABASE_URL first
        DATABASES = {"default": dj_database_url.parse(os.getenv("DATABASE_URL"), conn_max_age=600)}
        # dj-database-url may set OPTIONS like {'ssl-mode': 'REQUIRED'} which mysqlclient doesn't accept.
        opts = DATABASES["default"].get("OPTIONS", {})

        # If dj-database-url created 'ssl-mode', remove it and convert to proper 'ssl' dict if we have CA
        ssl_mode = opts.pop("ssl-mode", opts.pop("ssl_mode", None))
        if ssl_mode:
            # if user provided DATABASE_SSL_CA env, write it out and add it to OPTIONS['ssl']
            db_ssl_ca = os.getenv("DATABASE_SSL_CA")
            if db_ssl_ca:
                ca_file = Path(tempfile.gettempdir()) / "aiven_mysql_ca.pem"
                ca_file.write_text(db_ssl_ca.replace("\\n", "\n"))  # restore newlines if stored escaped
                opts.setdefault("ssl", {})["ca"] = str(ca_file)
            else:
                # If no CA, you can still keep ssl_mode by converting to underscore form
                opts["ssl_mode"] = ssl_mode

        # If DATABASE_SSL_CA present but dj-database-url didn't add ssl, ensure we attach the CA
        if "ssl" not in opts and os.getenv("DATABASE_SSL_CA"):
            ca_file = Path(tempfile.gettempdir()) / "aiven_mysql_ca.pem"
            ca_file.write_text(os.getenv("DATABASE_SSL_CA").replace("\\n", "\n"))
            opts.setdefault("ssl", {})["ca"] = str(ca_file)

        # write back cleaned options
        DATABASES["default"]["OPTIONS"] = opts

    else:
        # fallback to explicit env vars (keeps your previous logic)
        db_options = {}
        db_ssl_ca = os.getenv("DATABASE_SSL_CA")
        if db_ssl_ca:
            ca_file = Path(tempfile.gettempdir()) / "aiven_mysql_ca.pem"
            ca_file.write_text(db_ssl_ca.replace("\\n", "\n"))
            db_options["ssl"] = {"ca": str(ca_file)}

        DATABASES = {
            "default": {
                "ENGINE": "django.db.backends.mysql",
                "NAME": os.getenv("DATABASE_NAME", "wallpapers"),
                "USER": os.getenv("DATABASE_USER", "kenn"),
                "PASSWORD": os.getenv("DATABASE_PASSWORD", "123"),
                "HOST": os.getenv("DATABASE_HOST", "localhost"),
                "PORT": os.getenv("DATABASE_PORT", "3306"),
                "OPTIONS": db_options,
                "CONN_MAX_AGE": int(os.getenv("CONN_MAX_AGE", 600)),
            }
        }
    # -------------------------------------------------------------------

# Password validation: keep minimal in dev or enable in prod as you prefer
AUTH_PASSWORD_VALIDATORS = [] if DEBUG else [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",},
]

# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = os.getenv("TIME_ZONE", "UTC")
USE_I18N = True
USE_TZ = True

# Static & Media
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "image"]

# WhiteNoise storage
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# Custom user model
AUTH_USER_MODEL = "wallpapers.User"

# Rest Framework
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
}

# Stripe & email read from env
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_BASIC_PRICE_ID = os.getenv("STRIPE_BASIC_PRICE_ID", "")
STRIPE_PRO_PRICE_ID = os.getenv("STRIPE_PRO_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True").lower() in ("1", "true", "yes")
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", EMAIL_HOST_USER)

# Security headers you may want to enable later
CSP_SCRIPT_SRC = ("'self'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://unpkg.com")

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
