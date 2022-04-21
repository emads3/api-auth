from rest_framework import routers

from django.urls import include
from django.urls import path

router = routers.DefaultRouter()

urlpatterns = [
    path('', include('users.api.v1.urls')),
]
