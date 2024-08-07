from .models import *
from .serializers import *
from django.http import FileResponse
from rest_framework import status, viewsets
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from rest_framework.mixins import CreateModelMixin
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.viewsets import ModelViewSet, GenericViewSet
from rest_framework_simplejwt.authentication import JWTAuthentication


class RegisterViewSet(ModelViewSet):
    queryset = BaseUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    # http_method_names = ['post']
 
class LoginViewSet(viewsets.ViewSetMixin, TokenObtainPairView):
    # authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class WitnessViewSet(ModelViewSet):
    queryset=BaseUser.objects.filter(role='is_witness')
    serializer_class=WitnessSerializer


class ProfileViewSet(ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

    def get_serializer_context(self):
        return {'request': self.request}

class NotificationViewSet(ModelViewSet):
    queryset=Notification.objects.all()
    serializer_class=NotificationSerializer

class PropertyViewSet(ModelViewSet):
    queryset=Property.objects.all()
    serializer_class=PropertySerializer
    def destroy(self, request, *args, **kwargs):
        property=get_object_or_404(Property, pk=kwargs['pk'])
        property.delete()
        return super().destroy(request, *args, **kwargs)

class RentalConditionViewSet(ModelViewSet):
    queryset=RentalCondition.objects.all()
    serializer_class=RentalConditionSerializer

class ReportViewSet(CreateModelMixin,GenericViewSet):
    queryset=Report.objects.all()
    serializer_class=ReportSerializer

    
