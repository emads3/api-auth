from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet, GenericViewSet
from rest_framework.decorators import action
from rest_framework import permissions
from .permissions import IsOwnUserOrRaiseError
from .serializers import UserSerializer, TokenSerializer, UserAuthTokenSerializer, ChangePasswordSerializer, \
    UnauthenticatedUserSerializer, FullUserDetailsSerializer
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.models import AccessToken
from oauthlib import common


class UserViewSet(ModelViewSet):
    serializer_class = UserSerializer
    # queryset = get_user_model().objects.filter(is_active=True)
    # used get_user_model() instead of User because I used cuser package
    queryset = get_user_model().objects.all()

    def create(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            {'message': 'check email for verification token', 'data': serializer.data},
            status=status.HTTP_201_CREATED,
            headers=headers
        )

    def perform_create(self, serializer):
        user = serializer.save(is_active=False)
        # Send the mail
        mail_subject = 'your mail activation token'  # todo: localize this
        token = Token.objects.get_or_create(user=user)
        message = render_to_string('mail_activation.html', {'token': token})
        email = EmailMessage(mail_subject, message, to=[user.email])
        email.send()

    @action(detail=True, methods=['put'])
    def status(self, request, pk=None):
        serializer = TokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = self.get_object()

        try:
            Token.objects.get(user=user, key=serializer.data['token'])
        except Token.DoesNotExist:
            return Response(
                {'token': 'Wrong token for user.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Set the user as active.
        user.is_active = True
        user.save(update_fields=['is_active'])
        user_serializer = UserSerializer(
            user, context={'request': request})
        return Response(user_serializer.data)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        serializer = UnauthenticatedUserSerializer(queryset, many=True)

        if self.request.user and self.request.user.is_authenticated:
            serializer = FullUserDetailsSerializer(queryset, many=True)

        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = UnauthenticatedUserSerializer(instance)

        if self.request.user and self.request.user.is_authenticated:
            serializer = FullUserDetailsSerializer(instance)
        return Response(serializer.data)

    @action(
        detail=True,
        methods=['post'],
        permission_classes=[permissions.IsAuthenticated, IsOwnUserOrRaiseError]
    )
    def password(self, request, pk=None):
        user = self.get_object()
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save(user=user)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserAuthTokenViewSet(GenericViewSet):
    serializer_class = UserAuthTokenSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Generate token
        access_token = self._generate_access_token(serializer)
        return Response(
            {'token': access_token.token},
            status=status.HTTP_201_CREATED,
        )

    def _generate_access_token(self, serializer):
        user = get_user_model()
        user = user.objects.get(email=serializer.data['email'])

        expiration_dt = (
                timezone.datetime.now() +
                timezone.timedelta(
                    seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        )
        # No need to create an Application.
        access_token = AccessToken(
            user=user,
            expires=expiration_dt,
            token=common.generate_token()
        )
        access_token.save()

        return access_token
