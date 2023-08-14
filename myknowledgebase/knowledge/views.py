# knowledge/views.py
from django.forms import ValidationError
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseNotFound, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, render, redirect
from .forms import NewUserForm, PasswordResetForm, KBEntryForm, CustomPasswordChangeForm
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from .models import KBEntry, Tag, Audit, calculate_rating
from django.utils.html import strip_tags
from django.utils import timezone
import json

# Functions to be used inside Views

# -- This is to soft delete an article
def softDeleteArticle(article, user):
    article.deleted_datetime = timezone.now()
    article.deleted_by = user
    article.save()
    
# -- This can be used to 'undelete' an article
def undeleteArticle(article):
    article.deleted_datetime = None
    article.deleted_by = None
    article.save()

def register(request):
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            user = form.save()
            django_login(request, user)
            messages.success(request, "Registration successful.")
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
    articles = KBEntry.objects.none()  # Default to no entries

    if search_term:
        from django.db.models import Q
        articles = KBEntry.objects.filter(
            Q(title__icontains=search_term) |
            Q(article__icontains=search_term) |
            Q(meta_data__name__icontains=search_term) |
            Q(created_by__username__icontains=search_term),  # New condition for author's username
            deleted_datetime__isnull=True
        ).distinct()
        for article in articles:
            article.article = strip_tags(article.article.replace('<p>', ' '))

    # If search results are minimal or no query:
    if len(articles) < 5 or not search_term:
        newest_articles = KBEntry.objects.filter(deleted_datetime__isnull=True).order_by('-created_datetime')[:5]
        # Assuming you have a rating field which can be ordered
        top_rated_articles = KBEntry.objects.filter(deleted_datetime__isnull=True).order_by('-rating')[:5]
    else:
        newest_articles = []
        top_rated_articles = []

    context = {
        'entries': articles,
        'newest_articles': newest_articles,
        'top_rated_articles': top_rated_articles,
        'search_term': search_term
    }

    return render(request, 'knowledge/home.html', context)

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
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Updating the session hash prevents a password change from logging the user out.
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('home')
        else:
            messages.error(request, 'Please correct the error above.')
    else:
        form = CustomPasswordChangeForm(request.user)
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
def allarticles(request):
    if request.user.is_superuser:
        articles = KBEntry.objects.all()
    else:
        articles = KBEntry.objects.filter(deleted_datetime__isnull=True)
    
    return render(request, 'knowledge/all_articles.html', {'articles': articles})

@login_required
def article_detail(request, article_id):
    try:
        if request.user.is_superuser:
            # Superusers can view all articles, including deleted ones
            article = KBEntry.objects.get(pk=article_id)
        else:
            # Regular users can only view non-deleted articles
            article = KBEntry.objects.get(pk=article_id, deleted_datetime__isnull=True)
            
        # Increment the view count only if the article is not deleted
        if article.deleted_datetime is None:
            article.views += 1
            article.save()

    except KBEntry.DoesNotExist:
        messages.error(request, 'Article not found or has been deleted.')
        return redirect('home')
    
    user_has_upvoted = request.user in article.upvotes.all()
    user_has_downvoted = request.user in article.downvotes.all()
    
    context = {
        'article': article,
        'user_has_upvoted': user_has_upvoted,
        'user_has_downvoted': user_has_downvoted,
        'is_deleted': article.deleted_datetime is not None  # Indicates if the article is deleted
    }
    
    return render(request, 'knowledge/article_detail.html', context)



@login_required
def edit_article(request, article_id):
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
        return redirect(f'/article/{article_id}')  # Redirect to article detail or some other appropriate page

    if request.method == 'POST':
        form = KBEntryForm(request.POST, instance=article, request=request)
        if form.is_valid():
            form.save()           
            article.last_modified_by = request.user
            article.save()
            # Create an Audit record : Article Editted
            Audit(user=request.user, kb_entry=article, action_details=f"Editted Article : '{article.title[:50]}'").save()
            article.meta_data.clear()
            # Process tags
            tag_names = request.POST.get('meta_data', '').split(',')
            for tag_name in tag_names:
                tag_name = tag_name.strip()
                tag, created = Tag.objects.get_or_create(name=tag_name)
                article.meta_data.add(tag)

            # Redirect to the updated article or some success page
            return redirect(f'/article/{article_id}')

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
            article = form.save(commit=False)  # Temporarily save without committing to DB
            article.save()  # Save the KBEntry instance to the database
            # Create an Audit Entry for the Newly Created Article
            Audit(user=request.user, kb_entry=article, action_details=f"Created a new article: '{article.title[:50]}'").save()
            
            # Process tags
            tag_names = request.POST.get('meta_data', '').split(',')
            for tag_name in tag_names:
                tag_name = tag_name.strip()
                tag, created = Tag.objects.get_or_create(name=tag_name)
                article.meta_data.add(tag)

            messages.success(request, 'Your knowledge base entry was successfully created!')
            
            # Redirect to the article_detail view for the newly created article
            return redirect(f'/article/{article.id}')  # The URL pattern for article_detail is '/article/?id=ARTICLE_ID'
        
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
        softDeleteArticle(article, request.user)
        Audit(user=request.user, kb_entry=article, action_details=f"Soft deleted article: '{article.title[:50]}'").save()

        messages.success(request, 'Article successfully deleted.')
        return redirect('article_detail', article_id=article.id)

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

@login_required
def my_articles(request):
    user_articles = KBEntry.objects.filter(created_by=request.user, deleted_datetime__isnull=True)
    return render(request, 'knowledge/my_articles.html', {'articles': user_articles})

@login_required
def user_articles(request, user_id):
    try:
        # Fetch the user based on the provided user_id
        user_obj = User.objects.get(pk=user_id)
        
        # Fetch all articles created by this user and not deleted
        user_entries = KBEntry.objects.filter(created_by=user_obj, deleted_datetime__isnull=True)
        
        # Render the template with the user's articles
        return render(request, 'knowledge/user_articles.html', {'entries': user_entries, 'author': user_obj})
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('home')

@login_required
def upvote_article(request, article_id):
    try:
        article = KBEntry.objects.get(pk=article_id)
        # Assuming upvotes and downvotes are ManyToMany fields with the User model
        article.upvotes.add(request.user)
        article.downvotes.remove(request.user)  # remove downvote if user previously downvoted
        
        rating = calculate_rating(article)  # a function to calculate the rating
        article.rating = rating  # Saving the calculated rating to the article
        article.save()  # Committing the change to the database
        
        return JsonResponse({'status': 'success', 'rating': rating})
    except KBEntry.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Article not found'})

@login_required
def downvote_article(request, article_id):
    try:
        article = KBEntry.objects.get(pk=article_id)
        # Assuming upvotes and downvotes are ManyToMany fields with the User model
        article.upvotes.remove(request.user)
        article.downvotes.add(request.user)  # remove downvote if user previously downvoted
        
        rating = calculate_rating(article)  # a function to calculate the rating
        article.rating = rating  # Saving the calculated rating to the article
        article.save()  # Committing the change to the database
        
        return JsonResponse({'status': 'success', 'rating': rating})
    except KBEntry.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Article not found'})
    
@login_required
def undelete_article(request, article_id):
    article = get_object_or_404(KBEntry, pk=article_id)
    
    # Check if the user is a superuser
    if not request.user.is_superuser:
        messages.error(request, 'You do not have permission to undelete articles.')
        return redirect('home')
    
    # Check if the article is already undeleted
    if article.deleted_datetime is None:
        messages.info(request, 'This article is not deleted.')
        return redirect('article_detail', article_id=article.id)
    
    # Handle the POST request to confirm undeletion
    if request.method == 'POST':
        article.deleted_datetime = None
        article.save()
        # Add the audit entry for undeletion
        Audit(user=request.user, kb_entry=article, action_details=f"Undeleted article: '{article.title[:50]}'").save()
        
        messages.success(request, 'The article has been successfully undeleted.')
        return redirect('article_detail', article_id=article.id)
    
    # Render the confirmation template for undeletion
    return render(request, 'knowledge/confirm_undelete.html', {'article': article})

@login_required
def confirm_permanent_delete(request, article_id):
    try:
        article = KBEntry.objects.get(pk=article_id)
        if not request.user.is_superuser or not article.deleted_datetime:
            messages.error(request, 'You are not allowed to permanently delete any articles')
            return redirect('home')
        return render(request, 'knowledge/confirm_permanent_delete.html', {'article': article})
    except KBEntry.DoesNotExist:
        messages.error(request, 'Article not found.')
        return redirect('home')

@login_required
def perform_permanent_delete(request, article_id):
    try:
        article = KBEntry.objects.get(pk=article_id)
        if not request.user.is_superuser or not article.deleted_datetime:
            messages.error(request, 'You are not allowed to permanently delete any articles')
            return redirect('home')

        # Create a new audit log entry noting the permanent deletion BEFORE deleting the article
        Audit(user=request.user, action_details=f"Permanently deleted article: {article.title[:50]}").save()

        # Now, delete the article
        article.delete()

        messages.success(request, 'Article was permanently deleted.')
    except KBEntry.DoesNotExist:
        messages.error(request, 'Article not found.')

    return redirect('home')