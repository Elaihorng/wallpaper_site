from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.conf import settings

USER_TYPE_CHOICES = (
    ('Free', 'Free'),
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
)

class Subscription(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='subscription')
    plan = models.CharField(max_length=10, choices=PLAN_CHOICES, default='basic')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    downloads_used = models.PositiveIntegerField(default=0)  # counter for basic plan
    current_period_end = models.DateTimeField(null=True, blank=True)

    def downloads_remaining(self):
        if self.plan == 'pro':
            return None  # unlimited
        # basic quota: 10
        quota = 10
        return max(0, quota - self.downloads_used)

    def can_download_premium(self):
        if self.status != 'active':
            return False
        return self.plan == 'pro'

class DownloadLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    wallpaper = models.ForeignKey('Wallpaper', on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']
class User(AbstractUser):
    email = models.EmailField(unique=True)
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='Free')
    is_verified = models.BooleanField(default=False)

    REQUIRED_FIELDS = ['email']

    def can_download(self):
        return self.user_type == 'pro' and self.is_active and self.is_verified

class Wallpaper(models.Model):
    title = models.CharField(max_length=200)
    image = models.ImageField(upload_to='wallpapers/')
    is_premium = models.BooleanField(default=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.title

class Subscription(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='subscription')
    plan = models.CharField(max_length=20, choices=PLAN_CHOICES, default='basic')   # <- add this
    stripe_customer_id = models.CharField(max_length=200, blank=True, null=True)
    stripe_subscription_id = models.CharField(max_length=200, blank=True, null=True)
    status = models.CharField(max_length=50, default='inactive')
    downloads_used = models.PositiveIntegerField(default=0)  # keep if using basic quota
    current_period_end = models.DateTimeField(null=True, blank=True)

    def is_active(self):
        return self.status == 'active'

    def downloads_remaining(self):
        if self.plan == 'pro':
            return None
        return max(0, 10 - (self.downloads_used or 0))
