from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    ProfileViewSet,
    PropertyViewSet,
    NotificationViewSet,
    ReportViewSet,
    RentalConditionViewSet,
    RegisterViewSet,
    LoginViewSet,
    WitnessViewSet,
    ContactUsViewSet,
    PasswordResetViewSet,
    PasswordResetConfirmView
)

router = DefaultRouter()
router.register('profiles', ProfileViewSet)
router.register('property', PropertyViewSet)
router.register('notification', NotificationViewSet)
router.register('report', ReportViewSet)
router.register('rental', RentalConditionViewSet)
router.register('register',RegisterViewSet)
router.register('AddWitness',WitnessViewSet, basename='witness')
router.register('contactUs', ContactUsViewSet)
# urlpatterns=router.urls

urlpatterns = [
    path('login/', LoginViewSet.as_view({ 'post':'create'})),
    path('password_reset/', PasswordResetViewSet.as_view(), name='password_reset'),
    path('password_reset/confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('', include(router.urls)),
]
