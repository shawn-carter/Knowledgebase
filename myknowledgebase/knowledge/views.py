# knowledge/views.py
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseNotFound
from django.shortcuts import render, redirect
from .forms import NewUserForm, PasswordResetForm, KBEntryForm
from django.contrib.auth.forms import AuthenticationForm  # add this import
from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from .models import KBEntry, Tag
from django.utils.html import strip_tags
import json

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
    search_term = request.GET.get('search', '')
    entries = KBEntry.objects.none()  # Default to no entries

    if search_term:
        from django.db.models import Q
        entries = KBEntry.objects.filter(
            Q(title__icontains=search_term) |
            Q(article__icontains=search_term) |
            Q(meta_data__name__icontains=search_term)
        ).distinct()
        for entry in entries:
            entry.article = strip_tags(entry.article.replace('<p>', ' '))
    return render(request, 'knowledge/home.html', {'entries': entries, 'search_term': search_term})


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

@login_required
def create(request):
    if request.method == 'POST':
        form = KBEntryForm(request.POST, request=request)
        if form.is_valid():
            kb_entry = form.save(commit=False)  # Temporarily save without committing to DB
            kb_entry.save()  # Save the KBEntry instance to the database

            # Process tags
            tag_names = request.POST.get('meta_data', '').split(',')
            for tag_name in tag_names:
                tag_name = tag_name.strip()
                tag, created = Tag.objects.get_or_create(name=tag_name)
                kb_entry.meta_data.add(tag)
            messages.success(request, 'Your knowledge base entry was successfully created!')
            return redirect('home')  # This line should redirect to the home view after a successful save.
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = KBEntryForm(request=request)
    return render(request, 'knowledge/create.html', {'form': form})

@login_required
def kblist(request):
    entries = KBEntry.objects.all()  # get all KB Articles
    return render(request, 'knowledge/kb_list.html', {'entries': entries})

@login_required
def article_detail(request):
    article_id = request.GET.get('id', None)  # Get the id from the query parameter
    if not article_id:
        messages.error(request, 'Article ID not provided.')
        return redirect('home')

    try:
        article = KBEntry.objects.get(pk=article_id)
    except KBEntry.DoesNotExist:
        messages.error(request, 'Article not found.')
        return redirect('home')

    context = {
        'article': article
    }
    return render(request, 'knowledge/article_detail.html', context)

@login_required
def edit_article(request):
    article_id = request.GET.get('id')
    if not article_id:
        # Handle the case where no article_id is provided
        return HttpResponseBadRequest("Article ID is required.")
    
    all_tags = Tag.objects.all().values_list('name', flat=True)  # Move this line outside the try block

    # Fetch the article instance using the article_id
    try:
        article = KBEntry.objects.get(pk=article_id)
        associated_metatags = article.meta_data.all()
    except KBEntry.DoesNotExist:
        return HttpResponseNotFound("Article not found.")

    if request.method == 'POST':
        form = KBEntryForm(request.POST, instance=article, request=request)
        if form.is_valid():
            form.save()
            article.meta_data.clear()
            # Process tags
            tag_names = request.POST.get('meta_data', '').split(',')
            for tag_name in tag_names:
                tag_name = tag_name.strip()
                tag, created = Tag.objects.get_or_create(name=tag_name)
                article.meta_data.add(tag)

            # Redirect to the updated article or some success page
            return redirect(f'/article/?id={article_id}')

    else:
        form = KBEntryForm(instance=article, request=request)

    context = {
        'form': form,
        'article': article,
        'associated_metatags': [tag.name for tag in associated_metatags],
        'all_tags_json': json.dumps(list(all_tags))  # Serialize all_tags to JSON here
    }
    return render(request, 'knowledge/edit_article.html', context)

