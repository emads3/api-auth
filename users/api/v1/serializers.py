from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
import django.contrib.auth.password_validation as validators
from django.core import exceptions


class UserSerializer(serializers.HyperlinkedModelSerializer):
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=get_user_model().objects.all())])
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = get_user_model()
        fields = ['email', 'first_name', 'last_name', 'password']
        extra_kwargs = {
            'first_name': {'required': False},
            'last_name': {'required': False}
        }

    def validate(self, attrs):
        attrs['password'] = make_password(attrs.get('password'))
        return attrs


class TokenSerializer(serializers.Serializer):
    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass

    token = serializers.CharField()


class UserAuthTokenSerializer(serializers.Serializer):
    """ Serializer for `User` access token generation. """

    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        user = get_user_model()
        email = attrs.get('email')
        password = attrs.get('password')
        error_msg = {'detail': 'user with given credentials not found.'}

        try:
            user = user.objects.get(email=email, is_active=True)
        except user.DoesNotExist:
            raise serializers.ValidationError(error_msg)

        if not user.check_password(password):
            raise serializers.ValidationError(error_msg)

        return attrs


class ChangePasswordSerializer(serializers.HyperlinkedModelSerializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    new_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = get_user_model()
        fields = ('password', 'new_password')

    def validate(self, attrs):
        password = attrs.get('password')
        new_password = attrs.get('new_password')

        # user = self.context['request'].user
        user = None
        request = self.context.get("request")
        # print(self.context)

        if request and hasattr(request, "user"):
            user = request.user

        if not user.check_password(password):
            # todo: localize this msg
            raise serializers.ValidationError({'password': 'The password entered is incorrect.'})

        if password == new_password:
            # todo: localize this msg
            raise serializers.ValidationError({'password': 'New password should be different.'})

        try:
            validators.validate_password(password=new_password, user=user)
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({'new_password': list(e.messages)})

        return attrs

    def save(self, **kwargs):
        user = kwargs.get('user')
        user.set_password(self.validated_data['new_password'])
        user.save(update_fields=['password'])


class FullUserDetailsSerializer(serializers.Serializer):
    first_name = serializers.CharField(read_only=True)
    last_name = serializers.CharField(read_only=True)
    email = serializers.EmailField(read_only=True)

    class Meta:
        model = get_user_model()
        fields = ['first_name', 'last_name', 'email', 'is_active']


class UnauthenticatedUserSerializer(serializers.Serializer):
    first_name = serializers.CharField(read_only=True)

    class Meta:
        model = get_user_model()
        fields = ['first_name', 'is_active']
