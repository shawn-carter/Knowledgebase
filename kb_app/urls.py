# knowledge/urls.py

from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns = [
    # ---------- These URLS are for users who are not Authenticated ----------
    path("login/", views.login_view, name="login"),
    path('mfa/', views.mfa_view, name='mfa_view'),
    path("register/", views.register, name="register"),
    path("register_success/", views.register_success, name="register_success"),
    path("resetpassword/", views.password_reset_request, name="password_reset_request"),
    path("reset/<uidb64>/<token>/",views.password_reset_confirm,name="password_reset_confirm",),
    path("password_reset_complete/",views.password_reset_complete,name="password_reset_complete",),
    path('resetpassword/done/', views.password_reset_done, name='password_reset_done'),
    # ---------- These URLS are for Authenticated Users ----------
    path("", views.home, name="home"),
    path("changepassword/", views.changepassword, name="change_password"),
    path("create/", views.create, name="create"),
    path("article/<int:article_id>/", views.article_detail, name="article_detail"),
    path("edit/<int:article_id>/", views.edit_article, name="edit_article"),
    path("allarticles/", views.allarticles, name="allarticles"),
    path("myarticles/", views.my_articles, name="my_articles"),
    path("user_articles/<int:user_id>/", views.user_articles, name="user_articles"),
    path("article/<int:article_id>/upvote/", views.upvote_article, name="upvote_article"),
    path("article/<int:article_id>/downvote/",views.downvote_article,name="downvote_article",),
    path('confirm_logout/', views.confirm_logout, name='confirm_logout'),
    path("logout/", views.logout, name="logout"),
    
    # ---------- These URLS are ONLY for Super Users ----------
    path("auditlogs/", views.audit_logs, name="audit_logs"),
    path("users/", views.user_list, name="user-list"),
    path("toggle_user_active_status/<int:user_id>/",views.toggle_user_active_status,name="toggle_user_active_status",),
    path("delete_article/<int:article_id>/", views.delete_article, name="delete_article"),
    path('quick_delete_toggle/<int:article_id>/', views.quick_delete_toggle, name='quick_delete_toggle'),
    path("undelete_article/<int:article_id>/",views.undelete_article,name="undelete_article",),
    path("confirm_permanent_delete/<int:article_id>/",views.confirm_permanent_delete,name="confirm_permanent_delete",),
    path("perform_permanent_delete/<int:article_id>/",views.perform_permanent_delete,name="perform_permanent_delete",),
    path("manage_tags/", views.manage_tags, name="manage_tags"),
]
