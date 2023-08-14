# knowledge/urls.py

from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views
from .views import home, register, login_view, user_list,logout,changepassword,resetpassword, create, allarticles, article_detail, edit_article, delete_article, audit_logs, toggle_user_active_status, my_articles

urlpatterns = [
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('users/', user_list, name='user-list'),
    path('logout/', logout, name='logout'),
    path('changepassword/', changepassword, name='change_password'),
    path('resetpassword/', resetpassword, name='reset_password'),
    path('create/', create, name='create'),
    path('allarticles/', allarticles, name='allarticles'),
    path('article/<int:article_id>/', article_detail, name='article_detail'),
    path('edit/<int:article_id>/', edit_article, name='edit_article'),
    path('delete_article/<int:article_id>/', delete_article, name='delete_article'),
    path('auditlogs/', audit_logs, name='audit_logs'),
    path('toggle_user_active_status/<int:user_id>/',toggle_user_active_status, name='toggle_user_active_status'),
    path('myarticles/', my_articles, name='my_articles'),
    path('user_articles/<int:user_id>/', views.user_articles, name='user_articles'),
    path('article/<int:article_id>/upvote/', views.upvote_article, name='upvote_article'),
    path('article/<int:article_id>/downvote/', views.downvote_article, name='downvote_article'),
    path('', home, name='home'),
]