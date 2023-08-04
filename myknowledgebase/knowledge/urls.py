# knowledge/urls.py

from django.urls import path
from django.contrib.auth.views import LogoutView
from .views import home, register, login_view, user_list,logout,changepassword,resetpassword, create, kblist

urlpatterns = [
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('users/', user_list, name='user-list'),
    path('logout/', logout, name='logout'),
    path('changepassword/', changepassword, name='change_password'),
    path('resetpassword/', resetpassword, name='reset_password'),
    path('create/', create, name='create'),
    path('kblist/', kblist, name='kb_list'),
    path('', home, name='home'),
]