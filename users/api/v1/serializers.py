from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator


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
