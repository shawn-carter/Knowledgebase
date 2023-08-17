# knowledge/views.py

from django.db import models
from django.contrib import messages
from django.contrib.auth import authenticate, login as django_login, logout as django_logout,update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, render, redirect
from django.utils import timezone
from django.utils.html import strip_tags
from django.urls import reverse
from .forms import CustomPasswordChangeForm, KBEntryForm, NewUserForm, PasswordResetConfirmForm, RequestPasswordResetForm
from .models import KBEntry, Tag, Audit, calculate_rating
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

# -- This token_generator is required to generate Tokens for password reset requests
token_generator = PasswordResetTokenGenerator()

# ---------- All these views are for users who have not been authenticated ----------
def login_view(request):
    """
    Handles the user login process.

    - If the user is already authenticated, send them to 'home'

    - If the request is POST, it means the form has been submitted:
        - An instance of AuthenticationForm is created using the POST data.
        - If the form is valid, it attempts to authenticate the user with the given username and password.
        - If the user is authenticated successfully, they are logged in, a success message is added,
          and they are redirected to the 'home' page.
        - If the user is not authenticated, an error message is displayed.
        - If the form itself is not valid, an error message is displayed.

    - If the request is not POST (e.g., a GET request), an empty AuthenticationForm instance is created.
    
    - The function finally renders the 'knowledge/login.html' template, passing the form instance 
      in the context under the name 'login_form'.

    Parameters:
    - request (HttpRequest): The HTTP request object.

    Returns:
    - HttpResponse: The HTTP response object (the rendered template).
    """
    if request.user.is_authenticated:
        return redirect('home')
    
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
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            if not username or not password:
                if not username:
                    messages.error(request,"Username cannot be blank")
                if not password:
                    messages.error(request,"Password cannot be blank")
            else:
                messages.error(request,"Invalid username or password")
    form = AuthenticationForm()
    return render(request = request, template_name = "knowledge/login.html", context={"login_form":form})
    
def register(request):
    """
    Handles the user registration process.
    
    - If the user is already authenticated, send them to 'home'
    
    - If the request is POST, it means the form has been submitted:
        - An instance of NewUserForm is created using the POST data.
        - If the form is valid, the user is saved to the database, logged in,
          a success message is added, and the user is redirected to the 'home' page.
        - If the form is not valid, an error message is displayed.
    
    - If the request is not POST (e.g., a GET request), an empty NewUserForm instance is created.
    
    - The function finally renders the 'knowledge/register.html' template, passing the form instance 
      in the context under the name 'register_form'.

    Parameters:
    - request (HttpRequest): The HTTP request object.

    Returns:
    - HttpResponse: The HTTP response object (the rendered template).
    """
    if request.user.is_authenticated:
        return redirect('home')
    
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

def password_reset_request(request):
    """
    Handles the password reset request process.
        
    - If the user is already authenticated, send them to 'home'
    
    - If the request is POST, it means the form has been submitted:
        - An instance of RequestPasswordResetForm is created using the POST data.
        - If the form is valid, the function attempts to retrieve a user with the submitted email:
            - If a user with that email exists, a token is generated for that user.
            - A password reset link containing the user's ID and token is created (but, in this case,
              the link is displayed on a template rather than being sent via email).
            - The user is redirected to a template displaying the reset link.
            - If no user with that email exists, an error message is added to the form and displayed.
    
    - If the request is not POST (e.g., a GET request), an empty RequestPasswordResetForm instance is created.
    
    - The function finally renders the 'knowledge/password_reset_request.html' template, passing the form instance 
      in the context under the name 'form'.

    Parameters:
    - request (HttpRequest): The HTTP request object.

    Returns:
    - HttpResponse: The HTTP response object (the rendered template).
    """
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        form = RequestPasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                token = token_generator.make_token(user)
                # Normally, you'd email this link to the user
                reset_url = reverse('password_reset_confirm', args=[user.pk, token])
                # For now, just display it
                return render(request, 'knowledge/password_reset_link.html', {'reset_url': reset_url})
            except User.DoesNotExist:
                form.add_error(None, 'No account with this email address exists.')
                messages.error(request, 'No account with this email address exists.')
    else:
        form = RequestPasswordResetForm()
    return render(request, 'knowledge/password_reset_request.html', {'form': form})

def password_reset_confirm(request, user_id, token):
    """
    Handles the password reset confirmation process.
        
    - If the user is already authenticated, send them to 'home'
    
    - The function first attempts to retrieve a user with the provided user_id parameter.
        - If no user with that ID exists, the function redirects to a template that indicates an invalid token.
    
    - If a user with the provided ID is found, the function checks if the provided token is valid for that user:
        - If the token is invalid, the function redirects to a template that indicates an invalid token.
    
    - If the token is valid:
        - If the request is POST, it means the form has been submitted:
            - An instance of PasswordResetConfirmForm is created using the POST data.
            - If the form is valid, the user’s password is updated with the new password, 
              the user object is saved, and the user is redirected to the 'password_reset_complete' page.
        - If the request is not POST (e.g., a GET request), an empty PasswordResetConfirmForm instance is created.
    
    - The function finally renders the 'knowledge/password_reset_confirm.html' template, passing the form instance 
      in the context under the name 'form'.

    Parameters:
    - request (HttpRequest): The HTTP request object.
    - user_id (int): The ID of the user who requested the password reset.
    - token (str): The token required to verify the password reset request.

    Returns:
    - HttpResponse: The HTTP response object (the rendered template).
    """
    if request.user.is_authenticated:
        return redirect('home')
    
    try:
        user = User.objects.get(pk=user_id)
        if token_generator.check_token(user, token):
            if request.method == 'POST':
                form = PasswordResetConfirmForm(request.POST)
                if form.is_valid():
                    user.set_password(form.cleaned_data['new_password1'])
                    user.save()
                    return redirect('password_reset_complete')  # Redirect to the complete page
            else:
                form = PasswordResetConfirmForm()
            return render(request, 'knowledge/password_reset_confirm.html', {'form': form})
        else:
            # Token is invalid
            return render(request, 'knowledge/password_reset_invalid_token.html')
    except User.DoesNotExist:
        # Invalid user ID
        return render(request, 'knowledge/password_reset_invalid_token.html')

def password_reset_complete(request):
    """
    Renders a confirmation page after the user has successfully reset their password.
    
    - If the user is already authenticated, send them to 'home'
    
    This function is called after a user has successfully completed the password reset process.
    It renders a page that confirms the password has been changed successfully and informs the user
    that they can now log in with their new password.
    
    Parameters:
    - request (HttpRequest): The HTTP request object.
    
    Returns:
    - HttpResponse: The HTTP response object (the rendered template).
    """
    if request.user.is_authenticated:
        return redirect('home')
    
    return render(request, 'knowledge/password_reset_complete.html')
# ------------ End of non authenticated Views ----------

# ------------ The Views below are for Authenticated (logged in) Users ----------
@login_required
def logout(request):
    """
    Logs out the current user and redirects them to the home page.
    
    This view function is responsible for logging out the currently authenticated 
    user, displaying a success message indicating that they have been logged out, 
    and then redirecting them to the home page of the application.
    
    The user must be authenticated to access this view (as indicated by @login_required).
    
    Parameters:
    - request (HttpRequest): The HTTP request object.
    
    Returns:
    - HttpResponseRedirect: A redirect response object that redirects the user to the home page.
    """
    django_logout(request)
    messages.success(request, 'You were successfully logged out.')
    return redirect('login')

@login_required
def changepassword(request):
    """
    Allows an authenticated user to change their password.
    
    This view function displays a form to the authenticated user where they can 
    input their current password and a new password. If the form is submitted 
    and valid, it updates the user's password in the database.
    
    After the password is successfully changed, the user's session is updated 
    to prevent them from being logged out, and they are redirected to the 
    home page with a success message.
    
    If the form is invalid (e.g., current password is incorrect, new passwords 
    do not match, etc.), an error message is displayed.
    
    The user must be authenticated to access this view (as indicated by @login_required).
    
    Parameters:
    - request (HttpRequest): The HTTP request object.
    
    Returns:
    - HttpResponse: A rendered template in response to the request.
    - HttpResponseRedirect: A redirect response object that redirects the user to the home page if the form is valid.
    """
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

@login_required
def home(request):
    """
    Renders the home page of the knowledge base application.
    
    This view is responsible for handling the search functionality on the home page.
    It searches the knowledge base entries based on the user's search term and 
    displays the results. If no search term is provided or if the results are minimal,
    it displays the newest and top-rated articles.
    
    The user must be authenticated to access this view (as indicated by @login_required).
    
    Parameters:
    - request (HttpRequest): The HTTP request object, which may contain a GET parameter 'search'.
    
    Returns:
    - HttpResponse: The HTTP response object (the rendered template).
    
    Context Variables:
    - entries: The set of KBEntry objects that match the search term (if any).
    - newest_articles: A list of the 5 most recently created KBEntry objects.
    - top_rated_articles: A list of the 5 highest-rated KBEntry objects.
    - search_term: The search term entered by the user, if any.
    """
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
def create(request):
    """
    Allows an authenticated user to create a new knowledge base entry (Article).
    
    This view function displays a form to the authenticated user where they can 
    input the title and content of a new knowledge base entry, as well as associate
    it with tags (referred to as 'meta_data' in the code). 
    
    If the form is submitted and valid, it creates a new KBEntry instance in the database, 
    associates the specified tags with it, creates an audit log entry to record the creation 
    of the article, and then redirects the user to the detail view of the newly created article.
    
    If the form is invalid (e.g., required fields are missing or incorrect), an error message 
    is displayed.
    
    The user must be authenticated to access this view (as indicated by @login_required).
    
    Parameters:
    - request (HttpRequest): The HTTP request object.
    
    Returns:
    - HttpResponse: A rendered template in response to the request.
    - HttpResponseRedirect: A redirect response object that redirects the user to the detail page 
                            of the newly created article if the form is valid.
    """
    all_tags = Tag.objects.all().values_list('name', flat=True)  # Fetch all available tags
    
    if request.method == 'POST':
        form = KBEntryForm(request.POST, request=request)
        if form.is_valid():
            article = form.save(commit=False)  # Temporarily save without committing to DB
            article.last_modified_by = None
            article.save()  # Save the KBEntry instance to the database
            # Create an Audit Entry for the Newly Created Article
            Audit(user=request.user, kb_entry=article, action_details=f"Created a new article: '{article.title[:50]}'").save()
            
            # Process tags
            tag_names = request.POST.get('meta_data', '').split(',')
            for tag_name in tag_names:
                if tag_name:
                    tag_name = tag_name.strip()
                    tag, created = Tag.objects.get_or_create(name=tag_name)
                    article.meta_data.add(tag)

            messages.success(request, 'Your knowledge base entry was successfully created!')
            
            # Redirect to the article_detail view for the newly created article
            return redirect(f'/article/{article.id}')  # The URL pattern for article_detail is '/article/?id=ARTICLE_ID'
        
        else:
            messages.error(request, 'Please correct the error above.')
    else:
        form = KBEntryForm(request=request)
    print(all_tags)
    jsontags=json.dumps(list(all_tags))
    print(jsontags)
    context = {
        'form': form,
        'all_tags_json': json.dumps(list(all_tags))  # Serialize all_tags to JSON for the template
    }
    return render(request, 'knowledge/create.html', context)

@login_required
def article_detail(request, article_id):
    """
    Displays the detail page for a specific knowledge base entry (Article).
    
    This view function is responsible for fetching a specific KBEntry instance from 
    the database based on the given article_id and rendering its detail page.
    
    For superusers, this function allows access to all articles, including those marked as deleted.
    For regular users, this function only allows access to articles that are not marked as deleted.
    
    If a non-deleted article is accessed, its view count is incremented.
    
    If an article with the given article_id does not exist or is deleted (and the user is not a superuser), 
    an error message is displayed and the user is redirected to the home page.
    
    The user must be authenticated to access this view (as indicated by @login_required).
    
    Parameters:
    - request (HttpRequest): The HTTP request object.
    - article_id (int): The primary key of the KBEntry instance to display.
    
    Returns:
    - HttpResponse: A rendered template in response to the request, displaying the article details.
    - HttpResponseRedirect: A redirect response object that redirects the user to the home page if the 
                            article does not exist or is deleted (and the user is not a superuser).
    """
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
    """
    Allows authorized users to edit an existing knowledge base entry (article).
    
    This view function is responsible for handling the editing of an existing KBEntry instance.
    
    - Superusers and the original author of the article are authorized to edit it.
    - Deleted articles cannot be edited.
    - A user must be authenticated to access this view (as indicated by @login_required).
    
    The function fetches the article instance based on the given article_id, and displays a form populated 
    with the article's current data. When the form is submitted, the article's data is updated in the database.
    
    The function also handles updating the article's associated tags (meta_data).
    
    Parameters:
    - request (HttpRequest): The HTTP request object.
    - article_id (int): The primary key of the KBEntry instance to edit.
    
    Returns:
    - HttpResponse: A rendered template in response to the request, displaying the article editing form.
    - HttpResponseRedirect: A redirect response object that redirects the user to the updated article's 
                            detail page or some other appropriate page.
    - HttpResponseBadRequest: A 400 Bad Request response if no article_id is provided.
    """
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
            article.modified_datetime = timezone.now()
            print(article.modified_datetime)
            article.save()
            # Create an Audit record : Article Editted
            Audit(user=request.user, kb_entry=article, action_details=f"Editted Article : '{article.title[:50]}'").save()
            article.meta_data.clear()
            # Process tags
            tag_names = request.POST.get('meta_data', '').split(',')
            for tag_name in tag_names:
                if tag_name:
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
def allarticles(request):
    """
    Lists all the knowledge base entries (Articles) available to the user.
    
    This view function is responsible for displaying a list of all KBEntry instances (articles).
    
    - Superusers are able to view all articles, including those that have been soft-deleted.
    - Regular users can only view articles that have not been soft-deleted.
    - A user must be authenticated to access this view (as indicated by @login_required).
    
    Parameters:
    - request (HttpRequest): The HTTP request object.
    
    Returns:
    - HttpResponse: A rendered template in response to the request, displaying the list of articles.
    """
    if request.user.is_superuser:
        articles = KBEntry.objects.all()
    else:
        articles = KBEntry.objects.filter(deleted_datetime__isnull=True)
    
    return render(request, 'knowledge/all_articles.html', {'articles': articles})

@login_required
def my_articles(request):
    """
    Lists all the knowledge base entries (Articles) created by the currently logged-in user.

    This view function is responsible for displaying a list of all KBEntry instances (Articles) 
    that were created by the currently authenticated user and have not been soft-deleted.

    - A user must be authenticated to access this view (as indicated by @login_required).

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.

    Returns:
    - HttpResponse: A rendered template in response to the request, displaying the list of articles created by the current user.
    """
    user_articles = KBEntry.objects.filter(created_by=request.user, deleted_datetime__isnull=True)
    return render(request, 'knowledge/my_articles.html', {'articles': user_articles})

@login_required
def user_articles(request, user_id):
    """
    Lists all the knowledge base entries (articles) created by a specific user.

    This view function is responsible for displaying a list of all KBEntry instances (articles) 
    that were created by a specific user, identified by the user_id parameter, 
    and that have not been soft-deleted.

    - A user must be authenticated to access this view (as indicated by @login_required).
    - The function attempts to fetch a User object based on the provided user_id parameter.
    - If the User object is found, the function fetches all KBEntry instances (articles)
    that were created by this user and that have not been soft-deleted.
    - If no User object is found with the given user_id, the function redirects to the 'home' view 
    and displays an error message.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.
    - user_id (int): The ID of the user whose articles we want to list.

    Returns:
    - HttpResponse: A rendered template in response to the request, displaying the list of articles created by the specified user.
    - Redirect: If the user with the given user_id does not exist, redirects to the 'home' view with an error message.
    """
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
    """
    Allows an authenticated user to upvote a specific article (KBEntry instance).

    - A user must be authenticated to access this view (as indicated by @login_required).
    - The function attempts to fetch a KBEntry object based on the provided article_id parameter.
    - If the KBEntry object is found:
        - The user is added to the article's upvotes.
        - If the user had previously downvoted this article, that downvote is removed.
        - A new rating for the article is calculated and saved.
        - A JSON response is returned indicating success and the new rating value.
    - If no KBEntry object is found with the given article_id, a JSON response is returned indicating an error.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.
    - article_id (int): The ID of the article that the user wants to upvote.

    Returns:
    - JsonResponse: A JSON response indicating the success or failure of the action.
    """
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
    """
    Allows an authenticated user to downvote a specific article (KBEntry instance).

    - A user must be authenticated to access this view (as indicated by @login_required).
    - The function attempts to fetch a KBEntry object based on the provided article_id parameter.
    - If the KBEntry object is found:
        - The user is added to the article's downvotes.
        - If the user had previously upvoted this article, that upvote is removed.
        - A new rating for the article is calculated and saved.
        - A JSON response is returned indicating success and the new rating value.
    - If no KBEntry object is found with the given article_id, a JSON response is returned indicating an error.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.
    - article_id (int): The ID of the article that the user wants to downvote.

    Returns:
    - JsonResponse: A JSON response indicating the success or failure of the action.
    """
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
# ----------- This is the end of normal Authenticated User Views ----------

# ----------- The Views Below are restricted to 'superusers' ----------
@login_required
def audit_logs(request):
    """
    Displays a page with a list of all audit logs to the superuser.

    - Accessible only to authenticated users due to the @login_required decorator.
    - Checks if the user is a superuser:
        - If not, the user is redirected to the home page with an error message.
    - If the user is a superuser:
        - Fetches all Audit objects from the database and orders them by the action_datetime field in descending order.
        - Renders the 'knowledge/audit_logs.html' template with the context containing the fetched Audit objects.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.

    Returns:
    - HttpResponse: The rendered HTML page for superusers, or a redirect to the home page for non-superusers.
    """
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
def user_list(request):
    """
    Displays a page with a list of all user accounts to the superuser.

    - Accessible only to authenticated users due to the @login_required decorator.
    - Checks if the user is a superuser:
        - If not, the user is redirected to the home page with an error message.
    - If the user is a superuser:
        - Fetches all User objects from the database.
        - Renders the 'knowledge/user_list.html' template with the context containing the fetched User objects.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.

    Returns:
    - HttpResponse: The rendered HTML page for superusers, or a redirect to the home page for non-superusers.
    """
    if not request.user.is_superuser:
        messages.error(request, "You don't have permission to view this page.")
        return redirect('home')
    users = User.objects.all()  # get all users
    return render(request, 'knowledge/user_list.html', {'users': users})

@login_required
def toggle_user_active_status(request, user_id):
    """
    Toggles the active status of a user account.

    - Accessible only to authenticated users due to the @login_required decorator.
    - Checks if the user is a superuser:
        - If not, the user is redirected to the home page with an error message.
    - If the user is a superuser:
        - Attempts to fetch the User object that corresponds to the provided user_id parameter.
        - If the User object is not found, an error message is displayed, and the user is redirected to the user list page.
        - If the User object is found:
            - Checks if the user to be toggled is the same as the logged-in superuser:
                - If yes, an error message is displayed, indicating that the superuser cannot deactivate their own account.
                - If no, the active status (is_active attribute) of the User object is toggled (True becomes False, and vice versa).
                - Saves the updated User object to the database.
                - Displays a success message indicating whether the account has been activated or deactivated.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.
    - user_id (int): The ID of the user whose active status is to be toggled.

    Returns:
    - HttpResponse: Redirects to the user list page with a success message for superusers, or to the home page with an error message for non-superusers.
    """
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
def delete_article(request, article_id):
    """
    Handles the soft deletion of an article.

    - Accessible only to authenticated users due to the @login_required decorator.
    - Checks if the user is a superuser:
        - If not, the user is redirected to the home page with an error message.
    - If the user is a superuser:
        - Attempts to fetch the KBEntry object that corresponds to the provided article_id parameter.
        - If the KBEntry object is not found, an error message is displayed, and the user is redirected to the home page.
        - If the KBEntry object is found:
            - Handles a POST request to confirm the soft deletion of the article.
            - Calls a custom function (softDeleteArticle) to perform the soft deletion.
            - Creates an Audit entry to log the deletion action.
            - Displays a success message and redirects the user to the article detail page.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.
    - article_id (int): The ID of the article to be deleted.

    Returns:
    - HttpResponse: Redirects to the article detail page with a success message for superusers, or to the home page with an error message for non-superusers.
    """
    # Check if the user is a superuser
    if not request.user.is_superuser:
        messages.error(request, "You don't have permission to view this page.")
        return redirect('home')
    try:
        article = KBEntry.objects.get(pk=article_id)
    except KBEntry.DoesNotExist:
        messages.error(request, 'Article not found.')
        return redirect('home')  # or wherever you want to redirect to
       
    if request.method == "POST":
        softDeleteArticle(article, request.user)
        Audit(user=request.user, kb_entry=article, action_details=f"Soft deleted article: '{article.title[:50]}'").save()

        messages.success(request, 'Article successfully deleted.')
        return redirect('article_detail', article_id=article.id)

    return render(request, 'knowledge/confirm_delete.html', {'article': article})
    
@login_required
def undelete_article(request, article_id):
    """
    Handles the undeletion of a previously soft deleted article.

    - Accessible only to authenticated users due to the @login_required decorator.
    - Checks if the user is a superuser:
        - If not, the user is redirected to the home page with an error message.
    - Fetches the KBEntry object that corresponds to the provided article_id parameter.
        - Uses get_object_or_404 to automatically handle cases where the KBEntry object is not found.
    - If the KBEntry object is found:
        - Checks if the article is already undeleted (deleted_datetime is None):
            - If it is, an info message is displayed, and the user is redirected to the article detail page.
        - Handles a POST request to confirm the undeletion of the article.
        - Resets the deleted_datetime field to None, effectively undeleting the article.
        - Saves the updated KBEntry object to the database.
        - Creates an Audit entry to log the undeletion action.
        - Displays a success message and redirects the user to the article detail page.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.
    - article_id (int): The ID of the article to be undeleted.

    Returns:
    - HttpResponse: Redirects to the article detail page with a success message for superusers, or to the home page with an error message for non-superusers.
    """
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
    """
    Renders a confirmation page for permanent deletion of an article.

    - Accessible only to authenticated users due to the @login_required decorator.
    - Attempts to fetch the KBEntry object that corresponds to the provided article_id parameter.
    - Checks if the user is a superuser and if the article is in a deleted state (soft-deleted).
        - If not, the user is redirected to the home page with an error message.
    - If the KBEntry object is not found, an error message is displayed and the user is redirected to the home page.
    - If the KBEntry object is found and the user is a superuser:
        - Renders a confirmation page that asks the user to confirm the permanent deletion of the article.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.
    - article_id (int): The ID of the article to be permanently deleted.

    Returns:
    - HttpResponse: Renders the confirmation page for superusers, or redirects to the home page with an error message for non-superusers.
    """
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
    """
    Performs the permanent deletion of an article.

    - Accessible only to authenticated users due to the @login_required decorator.
    - Attempts to fetch the KBEntry object that corresponds to the provided article_id parameter.
    - Checks if the user is a superuser and if the article is in a deleted state (soft-deleted).
        - If not, the user is redirected to the home page with an error message.
    - If the KBEntry object is not found, an error message is displayed, and the user is redirected to the home page.
    - If the KBEntry object is found and the user is a superuser:
        - Creates a new Audit entry to log the permanent deletion action.
        - Permanently deletes the article from the database using the `delete` method.
        - Displays a success message indicating that the article was permanently deleted.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.
    - article_id (int): The ID of the article to be permanently deleted.

    Returns:
    - HttpResponse: Redirects to the home page with a success message for superusers, or with an error message for non-superusers.
    """
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

@login_required
def manage_tags(request):
    """
    Enables the superuser to manage tags, including viewing and deleting them.
    
    - Accessible only to authenticated users due to the @login_required decorator.
    - Checks if the user is a superuser:
        - If not, an error message is displayed, and the user is redirected to the home page.
    - If the request method is POST (which means a tag is being deleted):
        - Retrieves the ID of the tag to be deleted from the POST data.
        - Deletes the tag with the given ID from the database.
        - Redirects to the same 'manage_tags' page to reflect the deletion.
    - For all request methods (including GET):
        - Fetches all tags from the database.
        - Annotates each tag with the number of times it is used in articles.
        - Orders the tags by this count in descending order.
    
    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.

    Returns:
    - HttpResponse: Renders the 'manage_tags.html' template with the context data containing the tags.
                     For non-superusers, redirects to the home page with an error message.
    """
    if not request.user.is_superuser:
            messages.error(request, 'You are not allowed to manage Tags')
            return redirect('home')
    if request.method == 'POST':
        tag_id_to_delete = request.POST.get('tag_id')
        if tag_id_to_delete:
            Tag.objects.filter(id=tag_id_to_delete).delete()
            return redirect('manage_tags')
    
    # Fetch all tags, annotate them with the number of times they are used,
    # and order them by this count in descending order
    tags = Tag.objects.annotate(num_times_used=models.Count('kbentry')).order_by('-num_times_used')
    
    context = {'tags': tags}
    return render(request, 'knowledge/manage_tags.html', context)