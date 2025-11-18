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
        if sub.downloads_remaining() and sub.downloads_remaining() > 0:
            # Use transaction to avoid race conditions
            with transaction.atomic():
                # create log
                DownloadLog.objects.create(user=request.user, wallpaper=w)
                # increment counter
                # lock the row to avoid race (Postgres specific)
                sub.downloads_used = sub.downloads_used + 1
                sub.save(update_fields=['downloads_used'])
            return _serve_file_response(w)
        else:
            messages.warning(request, "Your Basic plan download quota is exhausted. Upgrade to Pro for unlimited downloads.")
            return redirect('wallpapers:subscribe')

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
        # build URLs using reverse to avoid hardcoded paths
        success_path = reverse('wallpapers:account') + '?session_id={CHECKOUT_SESSION_ID}'
        cancel_path = reverse('wallpapers:subscribe')
        success_url = request.build_absolute_uri(success_path)
        cancel_url = request.build_absolute_uri(cancel_path)

        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            customer_email=request.user.email,
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={"plan": plan},
        )


        # server-side redirect to Stripe-hosted checkout
        return redirect(checkout_session.url)
    except Exception as e:
        
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
@csrf_exempt
def stripe_webhook(request):
    # must set STRIPE_WEBHOOK_SECRET = 'whsec_....' in settings
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE', '')

    # verify signature if secret present
    webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)
    event = None
    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        else:
            # no secret configured — parse payload directly (not recommended for production)
            event = stripe.Event.construct_from(json.loads(payload), stripe.api_key)
    except ValueError as e:
        logger.exception("Invalid payload")
        return HttpResponseBadRequest()
    except stripe.error.SignatureVerificationError as e:
        logger.exception("Invalid signature")
        return HttpResponse(status=400)

    kind = event['type']
    data = event['data']['object']

    try:
        if kind == 'checkout.session.completed':
            # session completed — contains customer_email, customer, subscription, metadata
            handle_checkout_session_completed(data)
        elif kind in ('invoice.payment_succeeded', 'customer.subscription.created', 'customer.subscription.updated'):
            # these events include subscription object
            handle_subscription_event(data)
        else:
            logger.info("Unhandled stripe event type: %s", kind)
    except Exception as e:
        logger.exception("Error handling webhook event")
        # return 2xx? return 500 so Stripe will retry
        return HttpResponse(status=500)

    return HttpResponse(status=200)


def handle_checkout_session_completed(session):
    """
    session: the checkout.session object (dict)
    """
    email = session.get('customer_email')
    customer_id = session.get('customer')
    subscription_id = session.get('subscription')  # might be id or expanded object
    plan = session.get('metadata', {}).get('plan')  # if you used metadata

    # If subscription is expanded inside session, normalize it
    if isinstance(subscription_id, dict):
        subscription_id = subscription_id.get('id')

    if not email:
        logger.warning("checkout.session.completed without customer_email")
        return

    User = get_user_model()
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        # optionally create user; here we skip
        logger.warning("No user with email %s found for checkout.session.completed", email)
        return

    # safe DB update
    with transaction.atomic():
        sub, created = Subscription.objects.get_or_create(user=user)
        if customer_id:
            sub.stripe_customer_id = customer_id
        if subscription_id:
            sub.stripe_subscription_id = subscription_id

            # fetch full subscription to read status and current_period_end
            try:
                full_sub = stripe.Subscription.retrieve(subscription_id)
                status = full_sub.get('status')
                period_end = full_sub.get('current_period_end')
            except Exception:
                status = 'active'  # fallback
                period_end = None

            sub.status = 'active' if status in ('active', 'trialing') else status or sub.status
            if period_end:
                try:
                    sub.current_period_end = datetime.fromtimestamp(int(period_end), tz=timezone.utc)
                except Exception:
                    pass

        # update plan if present in metadata (or map price_id)
        if plan in ('basic', 'pro'):
            old_plan = sub.plan
            sub.plan = plan
            if sub.plan == 'basic' and (created or old_plan != 'basic'):
                sub.downloads_used = 0

        sub.save()

        # sync user.user_type
        if sub.status == 'active' and sub.plan == 'pro':
            user.user_type = 'pro'
        elif sub.status == 'active' and sub.plan == 'basic':
            user.user_type = 'basic'
        else:
            # optional: keep existing or set to free
            user.user_type = 'free'
        user.save()

    logger.info("Updated subscription for user %s from checkout.session.completed", user.email)


def handle_subscription_event(sub_obj):
    """
    Handle events where a subscription object is provided (invoice.payment_succeeded,
    customer.subscription.updated, etc.)
    """
    # sub_obj might either be a subscription object or an invoice containing subscription id
    sub_id = sub_obj.get('id') or sub_obj.get('subscription')
    if not sub_id:
        # invoice event with subscription id inside invoice.subscription
        sub_id = sub_obj.get('subscription')

    if not sub_id:
        logger.warning("subscription event without id")
        return

    try:
        full_sub = stripe.Subscription.retrieve(sub_id)
    except Exception as e:
        logger.exception("Failed to retrieve stripe subscription %s", sub_id)
        return

    customer_id = full_sub.get('customer')
    status = full_sub.get('status')
    plan_data = None
    try:
        items = full_sub.get('items', {}).get('data', [])
        if items:
            # price id and maybe product metadata
            price = items[0].get('price', {})
            plan_data = price.get('id')
    except Exception:
        pass

    # find user by stripe_customer_id
    try:
        sub = Subscription.objects.select_related('user').get(stripe_customer_id=customer_id)
        user = sub.user
    except Subscription.DoesNotExist:
        # fallback: try to find user by email through customer object
        try:
            cust = stripe.Customer.retrieve(customer_id)
            email = cust.get('email')
        except Exception:
            email = None

        if not email:
            logger.warning("Cannot find local subscription or customer email for stripe customer %s", customer_id)
            return

        User = get_user_model()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("No user found for email %s from stripe customer %s", email, customer_id)
            return
        # get_or_create subscription record
        sub, _ = Subscription.objects.get_or_create(user=user)

    # update local subscription
    with transaction.atomic():
        sub.stripe_subscription_id = sub_id
        sub.stripe_customer_id = customer_id
        sub.status = 'active' if status in ('active', 'trialing') else status
        # if full_sub has current_period_end
        try:
            pe = full_sub.get('current_period_end')
            if pe:
                from datetime import datetime, timezone as dt_timezone
                sub.current_period_end = datetime.fromtimestamp(int(pe), dt_timezone.utc)
        except Exception:
            pass

        # optional: map price id to plan name if you have mapping
        # e.g. if plan_data == settings.STRIPE_BASIC_PRICE_ID: sub.plan = 'basic'
        sub.save()

        # update user_type
        if sub.status == 'active' and sub.plan == 'pro':
            user.user_type = 'pro'
        elif sub.status == 'active' and sub.plan == 'basic':
            user.user_type = 'basic'
        else:
            user.user_type = 'free'
        user.save()

    logger.info("Updated subscription for user %s from subscription event", user.email)

def preview_wallpaper(request, pk):
    w = get_object_or_404(Wallpaper, pk=pk)

    # Suggested wallpapers (simple random style)
    suggested = Wallpaper.objects.exclude(pk=pk).order_by('?')[:8]

    return render(request, 'preview.html', {
        'w': w,
        'suggested': suggested,
    })


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

@login_required
def account(request):
    session_id = request.GET.get('session_id')
    session = None

    # Decode URL-encoded placeholder like %7BCHECKOUT_SESSION_ID%7D
    if session_id:
        session_id = unquote(session_id)

        # If the placeholder (or empty) was passed -> don't try to retrieve
        if '{CHECKOUT_SESSION_ID}' in session_id or session_id.strip() == '':
            messages.warning(
                request,
                "Stripe checkout did not return a valid session id"
            )
            session = None
        elif not session_id.startswith('cs_'):
            # Defensive: not a Stripe checkout session id
            messages.warning(request, "Invalid checkout session id received.")
            session = None
        else:
            try:
                session = stripe.checkout.Session.retrieve(session_id, expand=['subscription', 'customer'])
            except stripe.error.InvalidRequestError as e:
                messages.warning(request, f'Could not retrieve Stripe session: {str(e)}')
                session = None
            except Exception as e:
                logger.exception("Unexpected error retrieving stripe session: %s", e)
                messages.warning(request, "Could not retrieve Stripe session. Check server logs.")
                session = None

    # If session found, update DB from it (your existing logic can be reused here)
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

                sub_id = None
                status = None
                period_end = None

                if stripe_subscription:
                    if isinstance(stripe_subscription, dict):
                        sub_id = stripe_subscription.get('id')
                        status = stripe_subscription.get('status')
                        period_end = stripe_subscription.get('current_period_end')
                    else:
                        sub_id = stripe_subscription
                        try:
                            full_sub = stripe.Subscription.retrieve(sub_id)
                            status = full_sub.get('status')
                            period_end = full_sub.get('current_period_end')
                        except Exception:
                            status = 'active'

                    if sub_id:
                        sub.stripe_subscription_id = sub_id
                    if status:
                        sub.status = 'active' if status in ('active', 'trialing') else status

                    if period_end:
                        try:
                            pe_int = int(period_end)
                            sub.current_period_end = datetime.fromtimestamp(pe_int, dt_timezone.utc)
                        except Exception:
                            pass

                # update plan from metadata if present
                old_plan = sub.plan
                if plan in ('basic', 'pro'):
                    sub.plan = plan
                    if sub.plan == 'basic' and (created or old_plan != 'basic'):
                        sub.downloads_used = 0

                sub.save()

                # sync user_type
                if sub.status == 'active' and sub.plan == 'pro':
                    request.user.user_type = 'pro'
                elif sub.plan == 'basic' and sub.status == 'active':
                    request.user.user_type = 'basic'
                else:
                    request.user.user_type = 'free'
                request.user.save()

            messages.success(request, "Subscription status updated from checkout session.")
        except Exception as e:
            
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
                            try:
                                pe = stripe_subscription.get('current_period_end')
                                if pe:
                                    sub.current_period_end = datetime.fromtimestamp(int(pe), dt_timezone.utc)
                            except Exception:
                                pass
                            sub.save()

                            if sub.status == 'active' and sub.plan == 'pro':
                                request.user.user_type = 'pro'
                            elif sub.status == 'active' and sub.plan == 'basic':
                                request.user.user_type = 'basic'
                            else:
                                request.user.user_type = 'free'
                            request.user.save()
                        
        except Exception as e:
            logger.exception("Fallback lookup failed: %s", e)
            # keep UX simple; do not raise

    # final: always render the account page (so view never returns None)
    sub = getattr(request.user, 'subscription', None)
    remaining = None
    if sub:
        try:
            remaining = sub.downloads_remaining()
        except Exception:
            remaining = None

    return render(request, 'account.html', {'subscription': sub, 'remaining': remaining})
