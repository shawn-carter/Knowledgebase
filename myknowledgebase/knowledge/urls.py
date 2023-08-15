# knowledge/urls.py

from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views
from .views import home, register, login_view, user_list,logout,changepassword, create, allarticles, article_detail, edit_article, delete_article, audit_logs, toggle_user_active_status, my_articles, undelete_article, password_reset_request

urlpatterns = [
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('users/', user_list, name='user-list'),
    path('logout/', logout, name='logout'),
    path('changepassword/', changepassword, name='change_password'),
    path('create/', create, name='create'),
    path('allarticles/', allarticles, name='allarticles'),
    path('article/<int:article_id>/', article_detail, name='article_detail'),
    path('edit/<int:article_id>/', edit_article, name='edit_article'),
    path('delete_article/<int:article_id>/', delete_article, name='delete_article'),
    path('undelete_article/<int:article_id>/', undelete_article, name='undelete_article'),
    path('auditlogs/', audit_logs, name='audit_logs'),
    path('toggle_user_active_status/<int:user_id>/',toggle_user_active_status, name='toggle_user_active_status'),
    path('myarticles/', my_articles, name='my_articles'),
    path('user_articles/<int:user_id>/', views.user_articles, name='user_articles'),
    path('article/<int:article_id>/upvote/', views.upvote_article, name='upvote_article'),
    path('article/<int:article_id>/downvote/', views.downvote_article, name='downvote_article'),
    path('confirm_permanent_delete/<int:article_id>/', views.confirm_permanent_delete, name='confirm_permanent_delete'),
    path('perform_permanent_delete/<int:article_id>/', views.perform_permanent_delete, name='perform_permanent_delete'),    
    path('resetpassword/', views.password_reset_request, name='password_reset_request'),
    path('reset/<int:user_id>/<str:token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('password_reset_complete/', views.password_reset_complete, name='password_reset_complete'),
    path('', home, name='home'),
]