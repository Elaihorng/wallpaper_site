from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.conf import settings

USER_TYPE_CHOICES = (
    ('free', 'Free'),
    ('basic', 'Basic'),
    ('pro', 'Pro'),
)

PLAN_CHOICES = (
    ('basic', 'Basic'),
    ('pro', 'Pro'),
)

STATUS_CHOICES = (
    ('active', 'Active'),
    ('cancelled', 'Cancelled'),
    ('inactive', 'Inactive'),
)


class User(AbstractUser):
    email = models.EmailField(unique=True)
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='free')
    is_verified = models.BooleanField(default=False)

    REQUIRED_FIELDS = ['email']

    def can_download(self):
        # Example convenience: only pro users who are active and verified
        return self.user_type == 'pro' and self.is_active and self.is_verified


class Subscription(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='subscription')
    plan = models.CharField(max_length=20, choices=PLAN_CHOICES, default='basic')
    stripe_customer_id = models.CharField(max_length=200, blank=True, null=True)
    stripe_subscription_id = models.CharField(max_length=200, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='inactive')
    downloads_used = models.PositiveIntegerField(default=0)
    current_period_end = models.DateTimeField(null=True, blank=True)

    def is_active_subscription(self):
        return self.status == 'active'

    def downloads_remaining(self):
        """
        Returns:
          - int remaining downloads for basic plan
          - None for pro (unlimited)
        """
        if self.plan == 'pro':
            return None
        quota = 10
        used = self.downloads_used or 0
        return max(0, quota - used)

    def can_download_premium(self):
        """True if subscription is active and user has pro plan (or change as desired)."""
        return self.status == 'active' and self.plan == 'pro'

    def __str__(self):
        return f"Subscription(user={self.user_id}, plan={self.plan}, status={self.status})"


class Wallpaper(models.Model):
    title = models.CharField(max_length=200)
    image = models.ImageField(upload_to='wallpapers/')
    is_premium = models.BooleanField(default=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.title


class DownloadLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    wallpaper = models.ForeignKey(Wallpaper, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']
