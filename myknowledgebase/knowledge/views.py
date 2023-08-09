# knowledge/views.py
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseNotFound, HttpResponseForbidden
from django.shortcuts import render, redirect
from .forms import NewUserForm, PasswordResetForm, KBEntryForm
from django.contrib.auth.forms import AuthenticationForm  # add this import
from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from .models import KBEntry, Tag, Audit
from django.utils.html import strip_tags
from django.utils import timezone
import json

def soft_delete_article(article, user):
    article.deleted_datetime = timezone.now()
    article.deleted_by = user
    article.save()
    
def undelete_article(article):
    article.deleted_datetime = None
    article.deleted_by = None
    article.save()
    
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
            Q(meta_data__name__icontains=search_term),
            deleted_datetime__isnull=True
        ).distinct()
        for entry in entries:
            entry.article = strip_tags(entry.article.replace('<p>', ' '))
    return render(request, 'knowledge/home.html', {'entries': entries, 'search_term': search_term})


@login_required
def user_list(request):
    if not request.user.is_superuser:
        messages.error(request, "You don't have permission to view this page.")
        return redirect('home')
    users = User.objects.all()  # get all users
    return render(request, 'knowledge/user_list.html', {'users': users})

@login_required
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
def kblist(request):
    if not request.user.is_superuser:
        messages.error(request, "You don't have permission to view this page.")
        return redirect('home')
    entries = KBEntry.objects.all()  # get all KB Articles
    return render(request, 'knowledge/kb_list.html', {'entries': entries})

@login_required
def article_detail(request):
    article_id = request.GET.get('id', None)  # Get the id from the query parameter
    if not article_id:
        messages.error(request, 'Article ID not provided.')
        return redirect('home')

    try:
        article = KBEntry.objects.get(pk=article_id, deleted_datetime__isnull=True)
    except KBEntry.DoesNotExist:
        messages.error(request, 'Article not found or has been deleted.')
        return redirect('home')

    context = {
        'article': article,
        'author_name': article.created_by.username if article.created_by else None,
        'created_date': article.created_datetime,
        'last_modified_by': article.last_modified_by.username if article.last_modified_by else None,
        'last_modified_date': article.modified_datetime
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
        if article.deleted_datetime:  # Check if the article has been soft-deleted
            messages.error(request, 'This article has been deleted and cannot be edited.')
            return redirect('home')
        associated_metatags = article.meta_data.all()
    except KBEntry.DoesNotExist:
            messages.error(request, 'No article exists with this ID')
            return redirect('home')

    # Check if user is authorized to edit
    if not (request.user.is_superuser or article.created_by == request.user):
        messages.error(request, 'You are not authorized to edit this article.')
        return redirect(f'/article/?id={article_id}')  # Redirect to article detail or some other appropriate page

    if request.method == 'POST':
        form = KBEntryForm(request.POST, instance=article, request=request)
        if form.is_valid():
            form.save()           
            article.last_modified_by = request.user
            article.save()
            # Create an Audit record : Article Editted
            audit = Audit(user=request.user, kb_entry=article, action_details="Edited an article.")
            audit.save()
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

@login_required
def create(request):
    all_tags = Tag.objects.all().values_list('name', flat=True)  # Fetch all available tags
    
    if request.method == 'POST':
        form = KBEntryForm(request.POST, request=request)
        if form.is_valid():
            kb_entry = form.save(commit=False)  # Temporarily save without committing to DB
            kb_entry.save()  # Save the KBEntry instance to the database
            # Create an Audit Entry for the Newly Created Article
            audit = Audit(user=request.user, kb_entry=kb_entry, action_details="Created a new article.")
            audit.save()
            # Process tags
            tag_names = request.POST.get('meta_data', '').split(',')
            for tag_name in tag_names:
                tag_name = tag_name.strip()
                tag, created = Tag.objects.get_or_create(name=tag_name)
                kb_entry.meta_data.add(tag)

            messages.success(request, 'Your knowledge base entry was successfully created!')
            
            # Redirect to the article_detail view for the newly created article
            return redirect(f'/article/?id={kb_entry.id}')  # Assuming the URL pattern for article_detail is '/article/?id=ARTICLE_ID'
        
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = KBEntryForm(request=request)
    
    context = {
        'form': form,
        'all_tags_json': json.dumps(list(all_tags))  # Serialize all_tags to JSON for the template
    }
    return render(request, 'knowledge/create.html', context)

@login_required
def delete_article(request, article_id):
    if not request.user.is_superuser:
        messages.error(request, "You don't have permission to view this page.")
        return redirect('home')
    try:
        article = KBEntry.objects.get(pk=article_id)
    except KBEntry.DoesNotExist:
        messages.error(request, 'Article not found.')
        return redirect('home')  # or wherever you want to redirect to

    # Check if the user is a superuser
    if not request.user.is_superuser:
        messages.error(request, 'You are not authorized to delete this article.')
        return redirect('article_detail', id=article_id)

    if request.method == "POST":
        soft_delete_article(article, request.user)
        audit = Audit(user=request.user, kb_entry=article, action_details="Deleted an article.")
        audit.save()
        messages.success(request, 'Article successfully deleted.')
        return redirect('home')  # or wherever you want to redirect to after deletion

    return render(request, 'knowledge/confirm_delete.html', {'article': article})

@login_required
def audit_logs(request):
    if not request.user.is_superuser:
        messages.error(request, "You don't have permission to view this page.")
        return redirect('home')
    
    # Fetch all audit logs
    audits = Audit.objects.all().order_by('-action_datetime')  # Most recent actions first

    context = {
        'audits': audits
    }

    return render(request, 'knowledge/audit_logs.html', context)

@login_required
def toggle_user_active_status(request, user_id):
    # Check if the user is a superuser
    if not request.user.is_superuser:
        messages.error(request, "You do not have permission to perform this action.")
        return redirect('home')

    # Get the user by ID
    try:
        user_to_toggle = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('user-list')

    # Check if the user to toggle is the same as the logged-in superuser
    if user_to_toggle == request.user:
        messages.error(request, "You cannot deactivate your own account!")
        return redirect('user-list')

    # Toggle the user's active status
    user_to_toggle.is_active = not user_to_toggle.is_active
    user_to_toggle.save()

    # Provide feedback to the superuser
    if user_to_toggle.is_active:
        messages.success(request, f"{user_to_toggle.username}'s account has been activated.")
    else:
        messages.success(request, f"{user_to_toggle.username}'s account has been deactivated.")
    
    return redirect('user-list')