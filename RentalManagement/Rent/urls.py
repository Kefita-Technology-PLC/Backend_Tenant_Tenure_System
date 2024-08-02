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
    WitnessViewSet
)

router = DefaultRouter()
router.register('profiles', ProfileViewSet)
router.register('property', PropertyViewSet)
router.register('notification', NotificationViewSet)
router.register('report', ReportViewSet)
router.register('rental', RentalConditionViewSet)
router.register('register',RegisterViewSet)
router.register('AddWitness',WitnessViewSet, basename='witness')
# urlpatterns=router.urls

urlpatterns = [
    path('login/', LoginViewSet.as_view({ 'post':'create'})),
    path('', include(router.urls)),
]
