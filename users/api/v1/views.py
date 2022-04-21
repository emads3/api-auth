from django.contrib.auth import get_user_model
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from .serializers import UserSerializer


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
