# knowledge/views.py
from django.http import HttpResponse
from django.shortcuts import render, redirect
from .forms import NewUserForm, PasswordResetForm
from django.contrib.auth.forms import AuthenticationForm  # add this import
from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash

def register(request):
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            user = form.save()
            django_login(request, user)
            messages.success(request, "Registration successful." )
            return redirect("home")
        messages.error(request, "Unsuccessful registration. Invalid information.")
    else:
        form = NewUserForm()
    return render(request=request, template_name="knowledge/register.html", context={"register_form":form})

def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                django_login(request, user)
                messages.success(request, f"You are now logged in as {username}.")
                return redirect('home')
            else:
                messages.error(request,"Invalid username or password.")
        else:
            messages.error(request,"Invalid username or password.")
    form = AuthenticationForm()
    return render(request = request, template_name = "knowledge/login.html", context={"login_form":form})

@login_required
def home(request):
    return render(request, "knowledge/home.html")

@login_required
def user_list(request):
    users = User.objects.all()  # get all users
    return render(request, 'knowledge/user_list.html', {'users': users})

def logout(request):
    django_logout(request)
    messages.success(request, 'You were successfully logged out.')
    return redirect('home')  # or wherever you want to redirect to

@login_required
def changepassword(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Updating the session hash prevents a password change from logging the user out.
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('home')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'knowledge/change_password.html', {'form': form})

def resetpassword(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            new_password = form.cleaned_data.get('new_password1')
            user = get_user_model().objects.get(username=username)
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Your password was successfully updated!')
            return redirect('home')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordResetForm()
    return render(request, 'knowledge/reset_password.html', {'form': form})