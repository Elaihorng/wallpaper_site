# wallpapers/views.py
import json
import stripe
from datetime import datetime
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib import messages
from django.core.signing import Signer, BadSignature
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, FileResponse
from django import forms
from django.db.models import Q
from django.contrib import admin
from .models import Wallpaper, Subscription, User
from .forms import RegisterForm, LoginForm
from django.contrib.auth import get_user_model
from .models import Wallpaper, DownloadLog
from django.http import HttpResponseForbidden, FileResponse, HttpResponse
import os
from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from datetime import datetime, timezone as dt_timezone
import logging
from urllib.parse import unquote
from .models import Subscription
from django.utils import timezone
from django.db.models import F
from django.utils import timezone as dj_timezone


logger = logging.getLogger(__name__)

# Map your Stripe price IDs to plan names
PRICE_TO_PLAN = {
    "price_1ProIdxxxx": "pro",
    "price_1BasicIdxxxx": "basic",
    # add other price ids you use
}

# Simple idempotency using cache; optionally use DB model to persist processed event IDs.
from django.core.cache import cache
EVENT_CACHE_TTL = 60 * 60 * 24 * 7  

logger = logging.getLogger(__name__)
stripe.api_key = settings.STRIPE_SECRET_KEY

signer = Signer()
stripe.api_key = settings.STRIPE_SECRET_KEY
PLAN_PRICE_MAPPING = {
    'basic': settings.STRIPE_BASIC_PRICE_ID,
    'pro': settings.STRIPE_PRO_PRICE_ID,
}
# ---------- Basic pages / auth ----------
@login_required
def subscribe_page(request):
    return render(request, 'subscribe_page.html')

def home(request):
    q = request.GET.get('q', '').strip()
    if q:
        wallpapers = Wallpaper.objects.filter(
            Q(title__icontains=q) 
        ).order_by('-created_at')
    else:
        wallpapers = Wallpaper.objects.all().order_by('-created_at')

    context = {
        'wallpapers': wallpapers,
        'q': q,
    }
    print("SEARCH Q:", repr(q))   # temporary debug: watch runserver console
    return render(request, 'home.html', context)

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.is_verified = False
            user.save()
            token = signer.sign(user.email)
            verify_url = request.build_absolute_uri(reverse('wallpapers:verify_email', args=[token]))
            from django.core.mail import send_mail
            send_mail('Verify email', f'Click: {verify_url}', None, [user.email])
            messages.success(request, 'Account created. Check email for verification.')
            return redirect('wallpapers:login')
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})

def verify_email(request, token):
    try:
        email = signer.unsign(token)
    except BadSignature:
        messages.error(request, 'Invalid token')
        return redirect('wallpapers:home')
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        messages.error(request, 'User not found')
        return redirect('wallpapers:home')
    user.is_verified = True
    user.save()
    messages.success(request, 'Email verified')
    return redirect('wallpapers:login')

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('wallpapers:home')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

@login_required
def logout_view(request):
    logout(request)
    return redirect('wallpapers:home')

# ---------- Wallpaper views ----------
def wallpaper_detail(request, pk):
    w = get_object_or_404(Wallpaper, pk=pk)
    return render(request, 'detail.html', {'w': w})

def preview_wallpaper(request, pk):
    w = get_object_or_404(Wallpaper, pk=pk)
    return render(request, 'preview.html', {'w': w})

@login_required
def upload_wallpaper(request, pk):
    w = get_object_or_404(Wallpaper, pk=pk)
    if w.is_premium:
        try:
            sub = request.user.subscription
        except Subscription.DoesNotExist:
            return HttpResponseForbidden('Need active subscription')
        if sub.status != 'active':
            return HttpResponseForbidden('Subscription not active')
    return FileResponse(w.image.open('rb'), as_attachment=True, filename=w.image.name.split('/')[-1])

@require_POST
@login_required
def initiate_download(request, pk):
    # same checks as your download view but atomic and returns json
    try:
        w = Wallpaper.objects.get(pk=pk)
    except Wallpaper.DoesNotExist:
        return JsonResponse({'error': 'not_found'}, status=404)

    if w.is_premium:
        sub = getattr(request.user, 'subscription', None)
        if not sub or sub.status != 'active':
            return JsonResponse({'error': 'no_active_subscription'}, status=403)

        if sub.plan == 'basic':
            try:
                with transaction.atomic():
                    locked_sub = Subscription.objects.select_for_update().get(pk=sub.pk)
                    remaining = locked_sub.downloads_remaining() or 0
                    if remaining <= 0:
                        return JsonResponse({'error': 'quota_exhausted'}, status=403)

                    # log and increment
                    DownloadLog.objects.create(user=request.user, wallpaper=w)
                    if locked_sub.downloads_used is None:
                        Subscription.objects.filter(pk=locked_sub.pk).update(downloads_used=0)
                    Subscription.objects.filter(pk=locked_sub.pk).update(
                        downloads_used=F('downloads_used') + 1
                    )
                    locked_sub.refresh_from_db()
                    remaining = locked_sub.downloads_remaining() or 0
            except Exception:
                logger.exception("initiate_download error")
                return JsonResponse({'error': 'internal_error'}, status=500)
    else:
        # free or pro: optional logging
        try:
            DownloadLog.objects.create(user=request.user, wallpaper=w)
        except Exception:
            pass
        sub = getattr(request.user, 'subscription', None)
        remaining = sub.downloads_remaining() if sub and hasattr(sub, 'downloads_remaining') else None
        remaining = remaining or 0

    # build URL to actual download view (keeps existing permission checks there)
    download_url = request.build_absolute_uri(reverse('wallpapers:download_wallpaper', args=[w.pk]))
    return JsonResponse({'download_url': download_url, 'remaining': remaining})
def _extract_period_end_from_stripe_sub(stripe_sub):
    """
    Given a stripe subscription dict/object, try multiple ways to get an epoch
    integer for the subscription period end. Return an int epoch or None.
    """
    try:
        # If it's a dict-like object
        if isinstance(stripe_sub, dict):
            pe = stripe_sub.get("current_period_end")
            if pe:
                return int(pe)
            # fallback: latest_invoice -> lines -> period -> end
            inv = stripe_sub.get("latest_invoice")
            if isinstance(inv, dict):
                lines = inv.get("lines", {}).get("data", [])
                if lines:
                    period_end = lines[0].get("period", {}).get("end")
                    if period_end:
                        return int(period_end)
        else:
            # stripe library objects have attributes
            pe = getattr(stripe_sub, "current_period_end", None)
            if pe:
                return int(pe)
            inv = getattr(stripe_sub, "latest_invoice", None)
            if inv:
                lines = getattr(getattr(inv, "lines", None), "data", [])
                if lines:
                    period_end = getattr(getattr(lines[0], "period", None), "end", None)
                    if period_end:
                        return int(period_end)
    except Exception:
        # be silent here; caller will handle None
        pass
    return None


def _set_subscription_period_end_and_save(sub, period_end_epoch):
    """Convert epoch -> timezone-aware datetime and save on sub"""
    try:
        if period_end_epoch:
            sub.current_period_end = datetime.fromtimestamp(int(period_end_epoch), dj_timezone.utc)
            sub.save(update_fields=["current_period_end"])
            return True
    except Exception:
        pass
    return False

# ---------- Admin upload ----------
class WallpaperUploadForm(forms.ModelForm):
    class Meta:
        model = Wallpaper
        fields = ['title', 'image', 'is_premium']

User = get_user_model()

@login_required
def download_wallpaper(request, pk):
    w = get_object_or_404(Wallpaper, pk=pk)

    # If wallpaper is free -> let anyone logged in download (or even guests if desired)
    if not w.is_premium:
        return _serve_file_response(w)

    # Premium wallpaper
    if not request.user.is_authenticated:
        messages.info(request, "Please log in to download premium wallpapers.")
        return redirect(reverse('wallpapers:login') + f'?next={request.path}')

    # ensure subscription exists and is active
    sub = getattr(request.user, 'subscription', None)
    if not sub or sub.status != 'active':
        messages.info(request, "You need an active subscription to download premium images.")
        return redirect('wallpapers:subscribe')

    # Pro -> unlimited
    if sub.plan == 'pro':
        # log the download and serve
        DownloadLog.objects.create(user=request.user, wallpaper=w)
        return _serve_file_response(w)


    # Basic -> limited quota (10)
    if sub.plan == 'basic':
        try:
            with transaction.atomic():
                # re-fetch & lock the subscription row
                locked_sub = Subscription.objects.select_for_update().get(pk=sub.pk)

                remaining = locked_sub.downloads_remaining() or 0
                if remaining > 0:
                    # create log first
                    DownloadLog.objects.create(user=request.user, wallpaper=w)

                    # ensure downloads_used not None then atomically increment
                    if locked_sub.downloads_used is None:
                        Subscription.objects.filter(pk=locked_sub.pk).update(downloads_used=0)

                    Subscription.objects.filter(pk=locked_sub.pk).update(
                        downloads_used=F('downloads_used') + 1
                    )

                    return _serve_file_response(w)

        except Subscription.DoesNotExist:
            logger.exception("Subscription missing during download for user %s", request.user)
        except Exception:
            logger.exception("Error processing basic-plan download for user %s", request.user)

        messages.warning(request, "Your Basic plan download quota is exhausted. Upgrade to Pro for unlimited downloads.")
        return redirect('wallpapers:account')

    # default deny
    return HttpResponseForbidden("Cannot download this image.")


def _serve_file_response(wallpaper):
    # If you store files on disk and want to serve via Django (not recommended for heavy traffic)
    path = wallpaper.image.path
    filename = os.path.basename(path)
    response = FileResponse(open(path, 'rb'), as_attachment=True, filename=filename)
    return response

# ---------- Stripe checkout ----------
def subscribe_page(request):
    # show plan info and a form/button to start checkout
    return render(request, 'subscribe_page.html', {
        'stripe_public_key': settings.STRIPE_PUBLIC_KEY,
    })

@require_POST
@login_required
def create_checkout_session(request):
    stripe.api_key = settings.STRIPE_SECRET_KEY

    plan = request.POST.get('plan')
    if plan not in ('basic', 'pro'):
        messages.error(request, "Invalid plan selected.")
        return redirect('wallpapers:subscribe')

    # map plan -> price id from settings
    price_id = settings.STRIPE_BASIC_PRICE_ID if plan == 'basic' else settings.STRIPE_PRO_PRICE_ID
    if not price_id:
        messages.error(request, "Payment price is not configured. Contact admin.")
        return redirect('wallpapers:subscribe')

    try:
        # build base success/cancel urls and append placeholder explicitly to avoid encoding issues
        success_base = request.build_absolute_uri(reverse('wallpapers:account'))
        success_url = success_base + '?session_id={CHECKOUT_SESSION_ID}'
        cancel_url = request.build_absolute_uri(reverse('wallpapers:subscribe'))

        # include client_reference_id and metadata for robust lookup later
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            customer_email=request.user.email,
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=str(request.user.id),
            metadata={"plan": plan, "user_id": str(request.user.id)},
        )

        # server-side redirect to Stripe-hosted checkout
        return redirect(checkout_session.url)
    except Exception as e:
        logger.exception("Failed to create checkout session: %s", e)
        messages.error(request, f"Failed to create checkout session: {e}")
        return redirect('wallpapers:subscribe')


def preview_wallpaper(request, pk):
    w = get_object_or_404(Wallpaper, pk=pk)
    suggested = Wallpaper.objects.exclude(pk=pk).order_by('?')[:8]

    context = {
        'w': w,
        'suggested': suggested,
        'STRIPE_PUBLISHABLE_KEY': settings.STRIPE_PUBLISHABLE_KEY,
    }
    return render(request, 'preview.html', context)
# ---------- Stripe webhook (single, signature-verified) ----------


def preview_wallpaper(request, pk):
    w = get_object_or_404(Wallpaper, pk=pk)

    # Suggested wallpapers (simple random style)
    suggested = Wallpaper.objects.exclude(pk=pk).order_by('?')[:8]

    return render(request, 'preview.html', {
        'w': w,
        'suggested': suggested,
    })

import json
import logging
from django.conf import settings
from django.http import HttpResponse
from django.db import transaction
from django.utils import timezone as dt_timezone

logger = logging.getLogger(__name__)

# Map your Stripe price IDs to plan names
PRICE_TO_PLAN = {
    "price_1ProIdxxxx": "pro",
    "price_1BasicIdxxxx": "basic",
    # add other price ids you use
}

# Simple idempotency using cache; optionally use DB model to persist processed event IDs.
from django.core.cache import cache
EVENT_CACHE_TTL = 60 * 60 * 24 * 7  # keep processed ids for 7 days


def mark_event_processed(event_id):
    key = f"stripe_evt:{event_id}"
    # returns True if we set it now (not seen before)
    return cache.add(key, "1", EVENT_CACHE_TTL)


def was_event_processed(event_id):
    key = f"stripe_evt:{event_id}"
    return cache.get(key) is not None
@csrf_exempt
def stripe_webhook(request):
    # must set STRIPE_WEBHOOK_SECRET = 'whsec_....' in settings
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE', '')

    webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)
    event = None
    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        else:
            # no secret configured — parse payload directly (not recommended for production)
            event = stripe.Event.construct_from(json.loads(payload), stripe.api_key)
    except ValueError:
        logger.exception("Invalid payload")
        return HttpResponseBadRequest()
    except stripe.error.SignatureVerificationError:
        logger.exception("Invalid signature")
        return HttpResponse(status=400)

    kind = event.get('type')
    data = event.get('data', {}).get('object')

    try:
        if kind == 'checkout.session.completed':
            # We want the checkout session with expanded subscription & customer so downstream handlers
            # have the data they need (some stripe setups send subscription id only).
            try:
                session_id = data.get('id') if isinstance(data, dict) else None
                if session_id:
                    # expand subscription & customer to get full details
                    full_session = stripe.checkout.Session.retrieve(session_id, expand=['subscription', 'customer'])
                    handle_checkout_session_completed(full_session)
                else:
                    # fallback: pass whatever came in
                    handle_checkout_session_completed(data)
            except Exception:
                logger.exception("Failed to retrieve expanded checkout.session for webhook; passing raw data")
                handle_checkout_session_completed(data)

        elif kind in ('invoice.payment_succeeded', 'customer.subscription.created', 'customer.subscription.updated'):
            # these events include subscription object (may already be expanded)
            # pass the subscription object directly to handler
            subscription_obj = data
            handle_subscription_event(subscription_obj)
        else:
            logger.info("Unhandled stripe event type: %s", kind)

    except Exception:
        logger.exception("Error handling webhook event")
        # return 500 so Stripe will retry
        return HttpResponse(status=500)

    return HttpResponse(status=200)

def get_plan_from_subscription_object(sub_obj):
    """
    Given the Stripe subscription object (dict-like), inspect items -> price.id
    Return "pro", "basic", or None.
    """
    try:
        items = sub_obj.get("items", {}).get("data", [])
        if not items:
            return None
        # If multiple items exist you may want to inspect all and decide the dominant price.
        price = items[0].get("price") or {}
        price_id = price.get("id") or price.get("price")
        # try nickname or product metadata fallback:
        if price_id and price_id in PRICE_TO_PLAN:
            return PRICE_TO_PLAN[price_id]
        nickname = price.get("nickname")
        if nickname:
            nk = nickname.lower()
            if nk in ("pro", "basic"):
                return nk
        # fallback: product metadata/name
        prod = price.get("product")
        if isinstance(prod, dict):
            prod_name = prod.get("name", "").lower()
            if "pro" in prod_name:
                return "pro"
            if "basic" in prod_name:
                return "basic"
    except Exception as e:
        logger.exception("Failed to derive plan from subscription object: %s", e)
    return None


def update_subscription_and_user_from_stripe(sub_obj, customer_obj=None, user_email=None):
    """
    Update or create your Subscription row for the local user matching this Stripe subscription.
    Returns True on success, False otherwise.
    """
    from django.contrib.auth import get_user_model
    from .models import Subscription  # adjust import path to your app

    User = get_user_model()

    stripe_customer_id = None
    stripe_subscription_id = None
    status = None
    period_end = None

    # Normalize sub_obj: it may be a dict or stripe object
    try:
        if isinstance(sub_obj, dict):
            stripe_subscription_id = sub_obj.get("id")
            status = sub_obj.get("status")
            period_end = sub_obj.get("current_period_end") or sub_obj.get("current_period_end")
        else:
            stripe_subscription_id = getattr(sub_obj, "id", None)
            status = getattr(sub_obj, "status", None)
            period_end = getattr(sub_obj, "current_period_end", None)
    except Exception:
        logger.exception("Failed to parse subscription object")

    # Try to determine customer id
    if customer_obj:
        if isinstance(customer_obj, dict):
            stripe_customer_id = customer_obj.get("id")
        else:
            stripe_customer_id = getattr(customer_obj, "id", None)
    else:
        # subscription may carry customer
        if isinstance(sub_obj, dict):
            stripe_customer_id = sub_obj.get("customer")
        else:
            stripe_customer_id = getattr(sub_obj, "customer", None)

    # find local user: prefer stripe_customer_id, fallback to email
    user = None
    try:
        if stripe_customer_id:
            # assuming Subscription model stores stripe_customer_id and links to user
            try:
                sub = Subscription.objects.select_related("user").filter(stripe_customer_id=stripe_customer_id).first()
                if sub:
                    user = sub.user
            except Exception:
                logger.exception("Error looking up subscription by stripe_customer_id")
        if not user and user_email:
            user = User.objects.filter(email__iexact=user_email).first()
    except Exception:
        logger.exception("Error finding user for stripe subscription")

    if not user:
        logger.info("No local user found for customer_id=%s email=%s", stripe_customer_id, user_email)
        return False

    try:
        with transaction.atomic():
            sub, created = Subscription.objects.select_for_update().get_or_create(user=user)
            if stripe_customer_id:
                sub.stripe_customer_id = stripe_customer_id
            if stripe_subscription_id:
                sub.stripe_subscription_id = stripe_subscription_id

            # set status normalized
            if status:
                sub.status = "active" if status in ("active", "trialing") else status

            # set period end if available
            if period_end:
                try:
                    pe_int = int(period_end)
                    sub.current_period_end = dt_timezone.datetime.fromtimestamp(pe_int, dt_timezone.utc)
                except Exception:
                    # sometimes stripe returns datetime object already
                    try:
                        sub.current_period_end = period_end
                    except Exception:
                        pass

            # derive plan from subscription itself
            plan_from_sub = get_plan_from_subscription_object(sub_obj)
            if plan_from_sub:
                sub.plan = plan_from_sub

            # last fallback: if subscription metadata contains plan
            try:
                meta_plan = None
                if isinstance(sub_obj, dict):
                    meta_plan = sub_obj.get("metadata", {}).get("plan")
                else:
                    meta_plan = getattr(sub_obj, "metadata", {}).get("plan")
                if meta_plan in ("basic", "pro") and not sub.plan:
                    sub.plan = meta_plan
            except Exception:
                pass

            # reset downloads_used if downgrading to basic
            if sub.plan == "basic":
                sub.downloads_used = 0

            sub.save()

            # update user.user_type to mirror subscription
            if sub.status == "active" and sub.plan == "pro":
                user.user_type = "pro"
            elif sub.status == "active" and sub.plan == "basic":
                user.user_type = "basic"
            else:
                user.user_type = "free"
            user.save()
            user.refresh_from_db()

        logger.info("Updated subscription for user %s -> plan=%s status=%s", user.email, sub.plan, sub.status)
        return True
    except Exception:
        logger.exception("Failed to update local subscription and user")
        return False


def handle_checkout_session_completed(session_obj):
    """
    session_obj is the Stripe Checkout Session object (dict-like).
    It may contain 'subscription', 'customer', 'customer_email', and 'metadata'.
    """
    event_id = session_obj.get("id") or session_obj.get("session_id")
    if event_id and was_event_processed(event_id):
        logger.info("Skipping already-processed checkout.session.completed %s", event_id)
        return

    # Try to fetch expanded subscription if session.subscription is an id
    sub_obj = session_obj.get("subscription")
    customer_obj = None
    if isinstance(sub_obj, str):
        try:
            sub_obj = stripe.Subscription.retrieve(sub_obj, expand=["items.price.product"])
        except Exception:
            logger.exception("Failed to retrieve subscription by id from session")
            sub_obj = None

    # retrieve customer object optionally
    cust = session_obj.get("customer")
    if cust:
        if isinstance(cust, str):
            try:
                customer_obj = stripe.Customer.retrieve(cust)
            except Exception:
                logger.exception("Failed to retrieve customer by id from session")
                customer_obj = None
        else:
            customer_obj = cust

    user_email = session_obj.get("customer_email") or None

    success = False
    if sub_obj:
        success = update_subscription_and_user_from_stripe(sub_obj, customer_obj=customer_obj, user_email=user_email)
    else:
        # fallback: try to discover subscription from customer or email
        try:
            if customer_obj and getattr(customer_obj, "id", None):
                subs = stripe.Subscription.list(customer=customer_obj.id, limit=1)
                if subs and subs.get("data"):
                    success = update_subscription_and_user_from_stripe(subs["data"][0], customer_obj=customer_obj, user_email=user_email)
            elif user_email:
                customers = stripe.Customer.list(email=user_email, limit=1)
                if customers and customers.get("data"):
                    cust2 = customers["data"][0]
                    subs = stripe.Subscription.list(customer=cust2["id"], limit=1)
                    if subs and subs.get("data"):
                        success = update_subscription_and_user_from_stripe(subs["data"][0], customer_obj=cust2, user_email=user_email)
        except Exception:
            logger.exception("Fallback lookup failed in checkout.session handler")

    if event_id and success:
        mark_event_processed(event_id)


def handle_subscription_event(sub_obj):
    """
    sub_obj is a subscription object delivered by invoice.payment_succeeded,
    customer.subscription.created, or customer.subscription.updated events.
    """
    event_id = None
    try:
        # In webhook top-level event, caller should pass event id in envelope.
        # If not available here, caller must handle idempotency at a higher level.
        # We assume caller (stripe_webhook) checked event id and called mark_event_processed already.
        pass
    except Exception:
        pass

    # ensure subscription has items expanded for plan detection
    if isinstance(sub_obj, dict):
        # try expand items if items appear as ids (rare in webhook payload)
        items = sub_obj.get("items", {}).get("data", [])
        if not items:
            try:
                sub_obj = stripe.Subscription.retrieve(sub_obj.get("id"), expand=["items.price.product"])
            except Exception:
                logger.exception("Failed to expand subscription items")

    # attempt to find the user by customer id or by subscription.metadata
    cust_id = sub_obj.get("customer")
    email_from_meta = None
    try:
        email_from_meta = sub_obj.get("metadata", {}).get("customer_email")
    except Exception:
        email_from_meta = None

    customer_obj = None
    if cust_id:
        try:
            customer_obj = stripe.Customer.retrieve(cust_id)
        except Exception:
            logger.exception("Failed to retrieve customer for subscription_event")

    success = update_subscription_and_user_from_stripe(sub_obj, customer_obj=customer_obj, user_email=email_from_meta)
    return success


@login_required
def cancel_subscription(request):
    if request.method != "POST":
        return redirect("wallpapers:account")

    sub = getattr(request.user, "subscription", None)
    if not sub:
        messages.error(request, "No subscription record found.")
        return redirect("wallpapers:account")

    # try common field names
    stripe_id = getattr(sub, "stripe_subscription_id", None) \
             or getattr(sub, "stripe_id", None) \
             or getattr(sub, "subscription_id", None)

    # attempt to cancel on Stripe (if we have an id)
    if stripe_id:
        try:
            stripe.Subscription.delete(stripe_id)
        except Exception as e:
            # log or show error but continue to update local record
            messages.warning(request, f"Stripe cancel error (local record will still be updated): {e}")

    # Update local subscription record so template reflects the change
    sub.status = "canceled"           # or "inactive" depending on your choices
    sub.plan = ""                     # clear plan, or set to "basic"/"free" based on your app logic
    sub.current_period_end = None     # clear expiry
    sub.canceled_at = timezone.now()  # optional field, set if you have it
    sub.save()

    # Optionally update user's public type (what shows under username)
    # Choose the value that means "no paid plan" in your app. Example: "free" or ""
    try:
        request.user.user_type = getattr(request.user, "user_type", "") and "free" or "free"
        request.user.save()
    except Exception:
        # ignore if no user_type field or you prefer not to change it
        pass

    messages.success(request, "Subscription canceled.")
    return redirect("wallpapers:account")
# ---------- Account (single implementation with session handling) ----------
@login_required
def subscribe_page(request):
    session_id = request.GET.get('session_id')
    if session_id:
        try:
            # try to expand subscription & customer so we get more fields in response
            session = stripe.checkout.Session.retrieve(session_id, expand=['subscription', 'customer'])
        except Exception as e:
            messages.warning(request, f'Could not retrieve Stripe session: {str(e)}')
            session = None

        if session:
            # debug print to server console (can remove later)
            try:
                print('--- Stripe checkout session ---')
                print(json.dumps(session, default=str)[:4000])
            except Exception:
                print(session)

            # stripe returns either ids or expanded objects depending on expand
            stripe_subscription = session.get('subscription')
            stripe_customer_id = session.get('customer')
            # try to read plan metadata (should be set when creating the Checkout Session)
            plan = session.get('metadata', {}).get('plan')  # expected 'basic' or 'pro'

            # try to find subscription by listing if not included
            if not stripe_subscription and stripe_customer_id:
                try:
                    subs = stripe.Subscription.list(customer=stripe_customer_id, limit=1)
                    if subs and subs['data']:
                        stripe_subscription = subs['data'][0]
                except Exception as e:
                    print('Error listing stripe subscriptions:', e)

            try:
                user = request.user

                # Use select_for_update inside an atomic block when modifying subscription to avoid races
                with transaction.atomic():
                    sub, created = Subscription.objects.select_for_update().get_or_create(user=user)

                    # Save stripe customer id
                    if stripe_customer_id:
                        sub.stripe_customer_id = stripe_customer_id

                    # Determine subscription id, status, period_end
                    sub_id = None
                    status = None
                    period_end = None

                    if stripe_subscription:
                        # stripe_subscription may be an expanded dict or an id
                        if isinstance(stripe_subscription, dict):
                            sub_id = stripe_subscription.get('id') or stripe_subscription.get('stripe_id') or None
                            status = stripe_subscription.get('status')
                            period_end = stripe_subscription.get('current_period_end')
                        else:
                            # it's probably an id string
                            sub_id = stripe_subscription
                            try:
                                full_sub = stripe.Subscription.retrieve(sub_id)
                                status = full_sub.get('status')
                                period_end = full_sub.get('current_period_end')
                            except Exception as e:
                                print('Error retrieving full stripe subscription:', e)
                                # fallback to active
                                status = 'active'

                        # write subscription id and status
                        if sub_id:
                            sub.stripe_subscription_id = sub_id
                        if status:
                            sub.status = 'active' if status in ('active', 'trialing') else status

                        # parse period_end (may be epoch int or string)
                        if period_end:
                            try:
                                # ensure int
                                period_end_int = int(period_end)
                                dt = datetime.fromtimestamp(period_end_int, dt_timezone.utc)
                                sub.current_period_end = dt
                            except Exception:
                                # ignore parsing errors
                                pass

                    # If metadata plan present, update the plan
                    old_plan = sub.plan
                    if plan in ('basic', 'pro'):
                        sub.plan = plan
                        # If a user just switched to basic (or first time basic)
                        # reset their downloads_used so they get the quota again.
                        # Only reset when plan changed *to* basic or if subscription was just created.
                        if sub.plan == 'basic' and (created or old_plan != 'basic'):
                            sub.downloads_used = 0

                    # If there's no explicit plan metadata but session included price/product info
                    # you could map price IDs to plans here. Example (uncomment and adapt):
                    # price_id = session.get('display_items', [{}])[0].get('price', {}).get('id')  # older API
                    # map price_id -> plan

                    sub.save()

                    # ensure user's user_type reflects plan + active status
                    if sub.status == 'active' and sub.plan == 'pro':
                        user.user_type = 'pro'
                    else:
                        # For basic active subscription we show 'basic'; otherwise keep basic or none
                        user.user_type = sub.plan if sub.plan else 'basic'
                    user.save()

                messages.success(request, 'Subscription updated.')
            except Exception as e:
                print('Error updating DB from stripe session:', e)
                messages.error(request, 'Failed to update subscription status automatically. Check server logs.')

    # finally render current subscription
    sub = getattr(request.user, 'subscription', None)
    return render(request, 'subscribe_page.html', {'subscription': sub})

def plan_from_stripe_subscription_obj(stripe_sub):
    """
    Given a stripe Subscription object (dict-like), return 'pro', 'basic', or None.
    """
    try:
        items = stripe_sub.get("items", {}).get("data", [])
        if not items:
            return None
        # inspect first item (most checkouts have a single item)
        price = items[0].get("price") or {}
        price_id = price.get("id") or price.get("price")
        if price_id and price_id in PRICE_TO_PLAN:
            return PRICE_TO_PLAN[price_id]
        # fallback: price.nickname
        nickname = price.get("nickname")
        if nickname and nickname.lower() in ("pro", "basic"):
            return nickname.lower()
        # fallback: product name if expanded
        product = price.get("product")
        if isinstance(product, dict):
            pname = product.get("name", "").lower()
            if "pro" in pname:
                return "pro"
            if "basic" in pname:
                return "basic"
    except Exception:
        logger.exception("Failed to derive plan from subscription object")
    return None

@login_required
def account(request):
    # helper: try multiple places on a stripe subscription object/dict to find a period-end epoch
    def _extract_period_end_from_stripe_sub(stripe_sub):
        try:
            if isinstance(stripe_sub, dict):
                pe = stripe_sub.get("current_period_end")
                if pe:
                    return int(pe)
                inv = stripe_sub.get("latest_invoice")
                if isinstance(inv, dict):
                    lines = inv.get("lines", {}).get("data", [])
                    if lines:
                        period_end = lines[0].get("period", {}).get("end")
                        if period_end:
                            return int(period_end)
            else:
                pe = getattr(stripe_sub, "current_period_end", None)
                if pe:
                    return int(pe)
                inv = getattr(stripe_sub, "latest_invoice", None)
                if inv:
                    lines = getattr(getattr(inv, "lines", None), "data", [])
                    if lines:
                        period_end = getattr(getattr(lines[0], "period", None), "end", None)
                        if period_end:
                            return int(period_end)
        except Exception:
            pass
        return None

    session_id = request.GET.get('session_id')
    session = None

    if session_id:
        session_id = unquote(session_id)
        if '{CHECKOUT_SESSION_ID}' in session_id or session_id.strip() == '':
            messages.warning(request, "Stripe checkout did not return a valid session id")
            session = None
        elif not session_id.startswith('cs_'):
            logger.warning("Account view received non-cs_ session_id: %r for user %s", session_id, request.user.email)
            messages.warning(request, "Invalid checkout session id received.")
            session = None
        else:
            try:
                session = stripe.checkout.Session.retrieve(session_id, expand=['subscription', 'customer'])
            except stripe.error.InvalidRequestError as e:
                logger.exception("Could not retrieve Stripe session %s: %s", session_id, e)
                messages.warning(request, f'Could not retrieve Stripe session: {str(e)}')
                session = None
            except Exception as e:
                logger.exception("Unexpected error retrieving stripe session %s: %s", session_id, e)
                messages.warning(request, "Could not retrieve Stripe session. Check server logs.")
                session = None

    # If session found, update DB from it
    if session:
        try:
            stripe_subscription = session.get('subscription')
            stripe_customer_id = session.get('customer')
            plan = session.get('metadata', {}).get('plan')

            # fallback: if subscription not expanded, list by customer
            if not stripe_subscription and stripe_customer_id:
                try:
                    subs = stripe.Subscription.list(customer=stripe_customer_id, limit=1)
                    if subs and subs.get('data'):
                        stripe_subscription = subs['data'][0]
                except Exception as e:
                    logger.exception("Error listing subscriptions for customer: %s", e)

            with transaction.atomic():
                sub, created = Subscription.objects.select_for_update().get_or_create(user=request.user)
                if stripe_customer_id:
                    sub.stripe_customer_id = stripe_customer_id

                stripe_sub_obj = None
                if stripe_subscription:
                    if isinstance(stripe_subscription, dict):
                        stripe_sub_obj = stripe_subscription
                    else:
                        try:
                            stripe_sub_obj = stripe.Subscription.retrieve(
                                stripe_subscription,
                                expand=["items.price.product", "latest_invoice", "latest_invoice.payment_intent"]
                            )
                        except Exception:
                            try:
                                stripe_sub_obj = stripe.Subscription.retrieve(stripe_subscription)
                            except Exception:
                                stripe_sub_obj = None

                # robust extraction + final fallback
                pe_epoch = _extract_period_end_from_stripe_sub(stripe_sub_obj) if stripe_sub_obj else None

                if not pe_epoch and isinstance(stripe_subscription, str):
                    try:
                        full = stripe.Subscription.retrieve(
                            stripe_subscription,
                            expand=["latest_invoice", "items.price.product"]
                        )
                        pe_epoch = _extract_period_end_from_stripe_sub(full)
                        if full:
                            stripe_sub_obj = full
                    except Exception:
                        pass

                if pe_epoch:
                    try:
                        sub.current_period_end = datetime.fromtimestamp(int(pe_epoch), dt_timezone.utc)
                    except Exception:
                        pass

                # LOCAL FALLBACK (30 days) - guarantees a datetime
                if not sub.current_period_end:
                    from django.utils import timezone as dj_tz
                    sub.current_period_end = dj_tz.now() + dj_tz.timedelta(days=30)

                # debug: log what we will save
                logger.info("ACCOUNT VIEW: setting current_period_end=%s for user=%s (pe_epoch=%s)",
                            sub.current_period_end, request.user.username, pe_epoch)

                # save minimal fields now
                sub.save()

                # update plan if metadata exists
                old_plan = sub.plan
                if plan in ('basic', 'pro'):
                    sub.plan = plan
                    if sub.plan == 'basic' and (created or old_plan != 'basic'):
                        sub.downloads_used = 0

                # derive plan from stripe object if possible
                plan_from_sub = None
                if stripe_sub_obj:
                    plan_from_sub = plan_from_stripe_subscription_obj(stripe_sub_obj)
                if plan_from_sub:
                    sub.plan = plan_from_sub
                elif plan in ('basic', 'pro'):
                    sub.plan = plan

                if not sub.plan and stripe_sub_obj and isinstance(stripe_sub_obj, dict):
                    try:
                        items = stripe_sub_obj.get("items", {}).get("data", [])
                        if items:
                            price = items[0].get("price") or {}
                            price_id = price.get("id") or price.get("price")
                            if price_id and price_id in PRICE_TO_PLAN:
                                sub.plan = PRICE_TO_PLAN[price_id]
                    except Exception:
                        pass

                sub.save()

                # sync user_type immediately
                if sub.status == 'active' and sub.plan == 'pro':
                    request.user.user_type = 'pro'
                elif sub.status == 'active' and sub.plan == 'basic':
                    request.user.user_type = 'basic'
                else:
                    request.user.user_type = 'free'
                request.user.save()
                request.user.refresh_from_db()

            messages.success(request, "Subscription status updated from checkout session.")
        except Exception:
            logger.exception("Failed to update DB from stripe session")
            messages.error(request, "Failed to update subscription automatically. Check server logs or wait for webhook confirmation.")

    # If we still don't have a session or DB update, attempt fallback lookup by user email
    if session is None:
        try:
            if request.user.email:
                customers = stripe.Customer.list(email=request.user.email, limit=1)
                if customers and customers.get('data'):
                    cust = customers['data'][0]
                    subs = stripe.Subscription.list(customer=cust['id'], limit=1)
                    if subs and subs.get('data'):
                        stripe_subscription = subs['data'][0]
                        with transaction.atomic():
                            sub, created = Subscription.objects.select_for_update().get_or_create(user=request.user)
                            sub.stripe_customer_id = cust['id']
                            sub.stripe_subscription_id = stripe_subscription.get('id')
                            status = stripe_subscription.get('status')
                            sub.status = 'active' if status in ('active', 'trialing') else status or sub.status

                            # try to get period_end from stripe object
                            try:
                                pe = stripe_subscription.get('current_period_end')
                                if pe:
                                    sub.current_period_end = datetime.fromtimestamp(int(pe), dt_timezone.utc)
                            except Exception:
                                pass

                            # fallback local 30-day if still missing
                            if not sub.current_period_end:
                                from django.utils import timezone as dj_tz
                                sub.current_period_end = dj_tz.now() + dj_tz.timedelta(days=30)

                            logger.info("FALLBACK BRANCH: set current_period_end=%s for user=%s", sub.current_period_end, request.user.username)

                            p = get_plan_from_subscription_object(stripe_subscription)
                            if not p:
                                p = stripe_subscription.get('metadata', {}).get('plan')
                            if p in ('basic', 'pro'):
                                sub.plan = p
                            sub.save()

                            if sub.status == 'active' and sub.plan == 'pro':
                                request.user.user_type = 'pro'
                            elif sub.status == 'active' and sub.plan == 'basic':
                                request.user.user_type = 'basic'
                            else:
                                request.user.user_type = 'free'
                            request.user.save()
        except Exception:
            logger.exception("Fallback lookup failed")

    # final: always render the account page
    sub = getattr(request.user, 'subscription', None)
    remaining = None
    if sub:
        try:
            remaining = sub.downloads_remaining()
        except Exception:
            remaining = None

    return render(request, 'account.html', {'subscription': sub, 'remaining': remaining})

