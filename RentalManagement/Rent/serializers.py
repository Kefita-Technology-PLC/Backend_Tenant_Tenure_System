from rest_framework import serializers
from .models import *
from django.contrib.auth.hashers import make_password
from phonenumber_field.serializerfields import PhoneNumberField
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.conf import settings

# User registration serializer
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = BaseUser
        fields = [
            'id',
            'first_name',
            'father_name',
            'last_name',
            'region',
            'city',
            'sub_city',
            'unique_place',
            'house_number',
            'phone',
            'role',
            'password'
        ]
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

# User login serializer
class LoginSerializer(serializers.ModelSerializer):
    phone = PhoneNumberField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(request=self.context.get('request'), phone=data['phone'], password=data['password'])
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Invalid credentials.")

# Password reset request serializer
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not BaseUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user is associated with this email.")
        return value

    def create(self, validated_data):
        email = validated_data['email']
        user = BaseUser.objects.get(email=email)
        uidb64 = urlsafe_base64_encode(smart_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)
        current_site = get_current_site(self.context['request']).domain
        reset_link = f"http://{current_site}/password_reset/confirm/{uidb64}/{token}/"

        # Send the reset link via email
        send_mail(
            'Password Reset Request',
            f'Hi {user.first_name},\nUse the link below to reset your password:\n{reset_link}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        return validated_data

# Password reset confirmation serializer
class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(min_length=6)

    def validate(self, attrs):
        uidb64 = self.context['uidb64']
        token = self.context['token']
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = BaseUser.objects.get(pk=user_id)
        except (DjangoUnicodeDecodeError, BaseUser.DoesNotExist):
            raise serializers.ValidationError("Invalid user.")

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("The password reset link is invalid or has expired.")
        
        return attrs

    def save(self):
        uidb64 = self.context['uidb64']
        token = self.context['token']
        user_id = force_str(urlsafe_base64_decode(uidb64))
        user = BaseUser.objects.get(pk=user_id)
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        return user

# Other existing serializers...

class WitnessSerializer(serializers.ModelSerializer):
    class Meta:
        model = BaseUser
        fields = ['first_name', 'last_name', 'kebele_ID', 'role']

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['id', 'user', 'bio', 'profile_picture']

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'title', 'message', 'recipient', 'status']

class PropertySerializer(serializers.ModelSerializer):
    class Meta:
        model = Property
        fields = ['id', 'house_type', 'region', 'city', 'sub_city', 'kebele', 'unique_place', 'house_number', 'owner', 'number_of_rooms']

class RentalConditionSerializer(serializers.ModelSerializer):
    class Meta:
        model = RentalCondition
        fields = ['id', 'rent_amount', 'agreement_year', 'status']

class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model=Report
        fields=['id','type', 'name', 'description', 'attachment']

class ContactUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactUs
        fields = '__all__'

