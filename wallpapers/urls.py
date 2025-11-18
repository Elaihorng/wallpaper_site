from django.urls import path
from . import views

app_name = 'wallpapers'

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register_view, name='register'),
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('wallpaper/<int:pk>/', views.wallpaper_detail, name='wallpaper_detail'),
    path('download/<int:pk>/', views.download_wallpaper, name='download_wallpaper'),
    path('account/', views.account, name='account'),
    path('subscribe_page/', views.subscribe_page, name='subscribe_page'),
    path('wallpaper/<int:pk>/preview/', views.preview_wallpaper, name='wallpaper_preview'),
    
    path('subscribe/', views.create_checkout_session, name='subscribe'),
    path('create-checkout-session/', views.create_checkout_session, name='create_checkout_session'),
    path('stripe-webhook/', views.stripe_webhook, name='stripe_webhook'),
    path('upload/', views.upload_wallpaper, name='upload_wallpaper'),

]
