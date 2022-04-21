from django.urls import path
from django.urls import include

from django_rest.api.v1.urls import router

from .views import UserViewSet, UserAuthTokenViewSet

router.register(r'users', UserViewSet, basename='user')
router.register(r'login', UserAuthTokenViewSet, basename='user-auth')

urlpatterns = [
    path('', include(router.urls))
]
