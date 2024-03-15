# knowledge/views.py
from azure.communication.email import EmailClient
from datetime import timedelta
from django.db import models
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import (authenticate, login as django_login, logout as django_logout, update_session_auth_hash,get_user_model,)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, render, redirect
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.encoding import force_bytes
from django.utils.html import strip_tags
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from .forms import (
    CustomPasswordChangeForm,
    KBEntryForm,
    NewUserForm,
    PasswordResetConfirmForm,
    RequestPasswordResetForm
)

from .models import KBEntry, Tag, Audit, calculate_rating
import json, random, re

################################# Functions to be used inside Views

# -- This is to soft delete an article
def softDeleteArticle(article, user):
    """
    Soft deletes an article by marking it as deleted rather than removing it from the database.

    This function sets the 'deleted_datetime' field of the article to the current time, and records the user
    who performed the deletion in the 'deleted_by' field. It then saves these changes to the database.
    This approach allows the data to be retained for record-keeping or auditing purposes, and potentially restored later,
    rather than being permanently removed.

    Parameters:
    - article (Article): The article object that is to be soft deleted.
    - user (User): The user object representing the user who is performing the deletion.

    No explicit return value, but the article object is modified and saved within the function.
    """
    article.deleted_datetime = timezone.now()  # Set the deletion time to the current time
    article.deleted_by = user  # Record the user performing the deletion
    article.save()  # Save the changes to the database

# -- This can be used to 'undelete' an article
def undeleteArticle(article):
    """
    Reverses the soft deletion of an article, effectively 'undeleting' it.

    This function clears the 'deleted_datetime' and 'deleted_by' fields of the article, setting them to None,
    and saves the changes to the database. By removing these deletion markers, the article is no longer considered
    deleted in the context of the application, making it visible and accessible again as if it had never been deleted.

    Parameters:
    - article (Article): The article object that is to be undeleted.

    No explicit return value, but the article object is modified and saved within the function, making it 'active' again.
    """
    article.deleted_datetime = None  # Clear the deletion timestamp
    article.deleted_by = None  # Remove the record of who deleted the article
    article.save()  # Save the changes, effectively undeleting the article

def send_email(sender, recipient, subject, message):
    """
    Sends an email using Azure Communication Services.

    This function attempts to send an email by creating an email client using the Azure Communication Services connection string.
    It constructs the email message with the specified sender, recipient, subject, and message content.
    If the email is successfully sent, the function returns True. If an error occurs, it logs the exception and returns False.
    
    Parameters:
    - sender (str): The email address of the sender.
    - recipient (str): The email address of the recipient.
    - subject (str): The subject line of the email.
    - message (str): The plain text message body of the email.

    Returns:
    - bool: True if the email was successfully sent, False otherwise.
    """
    try:
        client = EmailClient.from_connection_string(settings.AZURE_COMMUNICATION_SERVICES_CONNECTION_STRING)

        email_message = {
            "senderAddress": sender,
            "recipients": {"to": [{"address": recipient}]},
            "content": {"subject": subject, "plainText": message},
        }

        poller = client.begin_send(email_message)
        result = poller.result()  # You might want to handle or log the result
        return True
    except Exception as e:
        print(e)  # Consider a more sophisticated error handling approach
        return False

def sanitize_tag(tag_name):
    """Remove any unwanted characters from tag names."""
    # Example: Allow only alphanumeric characters, spaces, and hyphens
    return re.sub(r'[^\w\s-]', '', tag_name)

def is_valid_tag(tag_name):
    """Check if the tag name meets defined criteria."""
    # Example criteria: non-empty, max length of 30 characters
    return tag_name and len(tag_name) <= 30

# Utility object for password reset process
token_generator = PasswordResetTokenGenerator()
"""
A PasswordResetTokenGenerator instance is used for generating secure tokens for password reset requests.
This object ensures that the password reset links are secure and can only be used once, providing a layer of security
against unauthorized password reset attempts.
"""

################################ End of Functions

################################# ---------- All these views are for users who have not been authenticated ----------

def login_view(request):
    """
    Manages the user login flow with additional steps for Multi-Factor Authentication (MFA) and auditing.

    - Redirects already authenticated users to the 'home' page.

    - For POST requests (form submissions):
        - Creates an AuthenticationForm instance with POST data.
        - Validates the form:
            - On success, attempts user authentication with provided credentials.
            - If authentication succeeds:
                - Logs an audit entry for a successful password attempt.
                - Generates a 6-digit MFA PIN and stores it in the session along with the user's ID and timestamp.
                - Sends the MFA PIN to the user's email address using Azure Communication Services Email Client.
                - Redirects the user to the MFA verification view ('mfa_view').
            - If authentication fails, logs an audit entry for a failed login attempt (including IP address) and shows an error message.
            - If the form is invalid due to missing username or password, displays appropriate error messages.

    - For non-POST requests, initializes an empty AuthenticationForm.

    - Renders the 'knowledge/login.html' template, passing the form as 'login_form' in the context.

    Parameters:
    - request (HttpRequest): The HTTP request object.

    Returns:
    - HttpResponse: The rendered login page or redirects to another view based on the login process.
    """
    if request.user.is_authenticated:
        return redirect("home")
    
    form = AuthenticationForm(request, data=request.POST) if request.method == "POST" else AuthenticationForm()
    if request.method == "POST":       
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:                
                #Add Audit entry for user provided correct password
                Audit(
                    user=user,
                    kb_entry=None,
                    action_details=f"User Provided Correct Password (Needs to provide MFA PIN)",                    
                ).save()
                # Generate a 6-digit PIN
                mfa_pin = random.randint(100000, 999999)
                request.session["mfa_pin"] = str(mfa_pin)
                request.session["authenticated_user_id"] = user.id  # Temporarily store user information
                request.session["mfa_created"] = timezone.now().isoformat()
                request.session["user_name"] = username
                # Send PIN via email (implement email sending logic here)
                connection_string = settings.AZURE_COMMUNICATION_SERVICES_CONNECTION_STRING
                client = EmailClient.from_connection_string(connection_string)
                to_email = user.email  # The user's email address
                subject = "Your MFA PIN"
                message = f"Your PIN is: {mfa_pin}"

                email_message = {
                    "senderAddress": "DoNotReply@mail.shwan.tech",
                    "recipients": {"to": [{"address": to_email}]},
                    "content": {"subject": subject, "plainText": message},
                }

                poller = client.begin_send(email_message)
                result = poller.result()  # Consider handling or logging the result

                # Redirect to MFA view
                return redirect('mfa_view')
            else:
                messages.error(request, "Invalid username or password")
        else:
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            if not username or not password:
                if not username:
                    messages.error(request, "Username cannot be blank")
                if not password:
                    messages.error(request, "Password cannot be blank")
            else:
                # Add audit log for unsuccessful login attempt
                ip_address = request.META.get('REMOTE_ADDR')               
                Audit(
                    user=None,
                    kb_entry=None,
                    action_details=f"Failed Login Attempt for username: {username}",
                    ip_address=ip_address
                ).save()
                messages.error(request, "Invalid username or password")
        
    return render(
        request=request,
        template_name="knowledge/login.html",
        context={"login_form": form},
    )

def mfa_view(request):
    """
    Handles the Multi-Factor Authentication (MFA) process for users.

    - Redirects authenticated users to the 'home' page to prevent re-authentication.

    - Retrieves the user based on the 'authenticated_user_id' stored in the session during the login process.
      - If the user cannot be found, displays an error message and redirects to the login page.

    - Checks if the MFA PIN has expired (30 minutes after creation).
      - If expired, displays an error message and redirects to the login page.

    - For POST requests (MFA PIN submission):
        - Compares the submitted PIN with the one stored in the session.
        - If the PIN matches:
            - Logs an audit entry for a successful login with MFA.
            - Logs the user in and clears all MFA-related session variables.
            - Displays a success message and redirects to the 'home' page.
        - If the PIN does not match:
            - Increments the 'mfa_attempts' session variable and logs an audit entry for the failed MFA attempt.
            - If the number of attempts reaches 4, clears the session and redirects to the login page with an error message.
            - Otherwise, displays an error message about the invalid PIN and re-renders the MFA page for another attempt.

    - For non-POST requests or if the user session or MFA PIN is not found, redirects to the login page.
      This ensures that users cannot access the MFA page without passing through the initial authentication steps.

    - Renders the 'knowledge/mfa.html' template for users to input their MFA PIN if conditions are met.

    Parameters:
    - request (HttpRequest): The HTTP request object.

    Returns:
    - HttpResponse: The rendered MFA page or redirects based on the authentication and MFA process status.
    """
    if request.user.is_authenticated:
        return redirect("home")
    
    User = get_user_model()
    user_id = request.session.get("authenticated_user_id")
    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            messages.error(request, "User not found. Please start the login process again.")
            return redirect("login")
    else:
        # If there's no user_id in the session, redirect to login page immediately.
        messages.error(request, "No authentication process detected. Please log in.")
        return redirect("login")
    
    pin_creation_str = request.session.get("mfa_created")
    if pin_creation_str:
        pin_creation_time = parse_datetime(pin_creation_str)
        if timezone.now() - pin_creation_time > timedelta(minutes=30):
            messages.error(request, "The PIN has expired. Please log in again.")
            return redirect("login")
    
    if request.method == "POST":
        # Ensure that this block only executes if there is a valid user object.
        if user:
            user_pin = request.POST.get("pin")
            attempts = request.session.get("mfa_attempts", 1)
            
            if user_pin == request.session.get("mfa_pin"):
                Audit(
                    user=user,
                    kb_entry=None,
                    action_details=f"User Logged in Successfully (Passed MFA)",
                ).save()
                django_login(request, user)  # Log in the user
                # Clear MFA-related session variables
                request.session.pop("mfa_pin", None)
                request.session.pop("mfa_created", None)
                request.session.pop("authenticated_user_id", None)
                request.session.pop("mfa_attempts", None) 
                messages.success(request, f"You are now logged in as {user.username}.")
                return redirect("home")
            else:
                request.session["mfa_attempts"] = attempts + 1
                Audit(
                    user=user,
                    kb_entry=None,
                    action_details=f"Failed MFA attempt {attempts}/3",
                    ip_address=request.META.get('REMOTE_ADDR')
                ).save()
                if request.session["mfa_attempts"] >= 4:
                    # Clear session data to force login again
                    request.session.pop("authenticated_user_id", None)
                    request.session.pop("mfa_created", None)
                    request.session.pop("mfa_attempts", None)
                    messages.error(request, "Maximum MFA attempts reached. Please log in again.")
                    return redirect("login")
                
                messages.error(request, "Invalid PIN. Please try again.")
                return render(request, "knowledge/mfa.html")
        else:
            # This condition should already be handled by the earlier redirect, but it's good to have a safeguard.
            return redirect("login")
    else:
        if not user or "mfa_pin" not in request.session:
            return redirect("login")
        return render(request, "knowledge/mfa.html")

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
        return redirect("home")

    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Registration successful.")
            return redirect("register_success")
        messages.error(request, "Unsuccessful registration. Invalid information.")
    else:
        form = NewUserForm()
    return render(
        request=request,
        template_name="knowledge/register.html",
        context={"register_form": form},
    )

def register_success(request):
    # Your view logic here
    return render(request, 'knowledge/register_success.html')

def password_reset_request(request):
    """
    Manages the process for requesting a password reset.

    - Redirects authenticated users to the 'home' page to prevent them from using this function.

    - For POST requests (form submissions):
        - Instantiates the RequestPasswordResetForm with the submitted data.
        - Validates the form:
            - If valid, it attempts to find a user with the provided email.
                - If a user is found:
                    - Generates a password reset token for the user.
                    - Encodes the user's ID in a URL-safe base64 format.
                    - Constructs a password reset URL with the user's ID and token.
                    - Attempts to send a password reset email to the user's email address with the reset link.
                        - If the email is successfully sent, displays a success message and redirects to a page indicating
                          the password reset email has been sent ('password_reset_done').
                        - If the email fails to send, displays an error message to the user.
                - If no user is found with the provided email, displays an error message.
            - If the form is not valid (e.g., invalid email format), displays an error message.

    - For non-POST requests, or initially, displays an empty RequestPasswordResetForm for the user to fill in.

    - Renders the 'knowledge/password_reset_request.html' template, passing the form in the context as 'form'.

    Parameters:
    - request (HttpRequest): The HTTP request object.

    Returns:
    - HttpResponse: The response object rendering the template, or redirects as per the logic.
    """
    if request.user.is_authenticated:
        return redirect("home")

    if request.method == "POST":
        form = RequestPasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            try:
                user = User.objects.get(email=email)
                token = token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                reset_url = request.build_absolute_uri(
                    reverse("password_reset_confirm", kwargs={'uidb64': uid, 'token': token})
                )
                
                # Send the password reset email
                if send_email(
                    sender="DoNotReply@mail.shwan.tech",
                    recipient=email,
                    subject="Password Reset Request",
                    message=f"Please click the link to reset your password: {reset_url}"
                ):
                    messages.success(request, "A password reset link has been sent to your email.")
                else:
                    messages.error(request, "Failed to send password reset email.")

                return redirect("password_reset_done")
            except User.DoesNotExist:
                messages.error(request, "No account with this email address exists.")
        else:
             messages.error(request, "Please enter a valid email address")  
    else:
        form = RequestPasswordResetForm()
    return render(request, "knowledge/password_reset_request.html", {"form": form})

def password_reset_done(request):
    # Your view logic here
    return render(request, 'knowledge/password_reset_done.html')

def password_reset_confirm(request, uidb64, token):
    """
    Manages the password reset confirmation process after a user clicks on the password reset link.

    - Redirects authenticated users to the 'home' page to prevent access to this page.

    - Decodes the base64-encoded user ID (uidb64) and attempts to retrieve the corresponding user.
        - If no matching user is found, renders a template indicating an invalid or expired link.

    - Verifies the reset token against the user:
        - If the token is valid, proceeds with the password reset process:
            - For POST requests, indicating form submission:
                - Instantiates the PasswordResetConfirmForm with POST data.
                - If the form is valid, updates the user's password with the new one provided in the form, saves the user object,
                  and redirects to the 'password_reset_complete' page, indicating a successful password reset.
            - For non-POST requests (e.g., GET), displays an empty PasswordResetConfirmForm for the user to fill in.
        - If the token is invalid, renders a template indicating an invalid or expired link.

    - Renders the 'knowledge/password_reset_confirm.html' template with the password reset form, or the invalid token template based on the conditions met.

    Parameters:
    - request (HttpRequest): The HTTP request object.
    - uidb64 (str): The base64-encoded ID of the user who requested the password reset.
    - token (str): The token for verifying the password reset request's validity.

    Returns:
    - HttpResponse: The rendered template for the password reset confirmation or invalid token page.
    """
    if request.user.is_authenticated:
        return redirect("home")

    try:
        # Decode uidb64 to user_id
        user_id = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=user_id)
        if token_generator.check_token(user, token):
            if request.method == "POST":
                form = PasswordResetConfirmForm(request.POST)
                if form.is_valid():
                    user.set_password(form.cleaned_data["new_password1"])
                    user.save()
                    return redirect(
                        "password_reset_complete"
                    )  # Redirect to the complete page
            else:
                form = PasswordResetConfirmForm()
            return render(
                request, "knowledge/password_reset_confirm.html", {"form": form}
            )
        else:
            # Token is invalid
            return render(request, "knowledge/password_reset_invalid_token.html")
    except User.DoesNotExist:
        # Invalid user ID
        return render(request, "knowledge/password_reset_invalid_token.html")

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
        return redirect("home")

    return render(request, "knowledge/password_reset_complete.html")

################################# ------------ End of non authenticated Views ----------


################################# ------------ The Views below are for Authenticated (logged in) Users ----------

@login_required
def confirm_logout(request):
    """ 
    Brings up a confirmation request asking user if they are sure they want to log out
        - If the user clicks Yes then they are redirected to the actual logout view.
        - Otherwise they are redirected to the home view
        
        *This was added after seeing that confirmation was required when leaving the application.
        
        The user must be authenticated to access this view (as indicated by @login_required).

    Parameters:
    - request (HttpRequest): The HTTP request object.

    Returns:
    - HttpResponseRedirect: A redirect response object that redirects the user to logout
    """
    if request.method == 'POST':
        return redirect('logout')
    return render(request, 'knowledge/confirm_logout.html')

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
    Audit(
        user=request.user,
        kb_entry=None,
        action_details=f"User Logged Out",
        ).save()
    django_logout(request)
    messages.success(request, "You were successfully logged out.")
    return redirect("login")

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
    if request.method == "POST":
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Updating the session hash prevents a password change from logging the user out.
            update_session_auth_hash(request, user)
            messages.success(request, "Your password was successfully updated!")
            return redirect("home")
        else:
            messages.error(request, "Please correct the error above.")
    else:
        form = CustomPasswordChangeForm(request.user)
    return render(request, "knowledge/change_password.html", {"form": form})

@login_required
def home(request):
    """
    Renders the home page of the knowledge base application.

    This view is responsible for handling the search functionality on the home page.
    It searches the knowledge base articles based on the user's search term and
    displays the results. If no search term is provided or if the number of articles is less than 5,
    it displays the newest and top-rated articles.

    The user must be authenticated to access this view (as indicated by @login_required).

    Parameters:
    - request (HttpRequest): The HTTP request object, which may contain a GET parameter 'search'.

    Returns:
    - HttpResponse: The HTTP response object (the rendered template).

    Context Variables:
    - articles: The set of KBEntry objects that match the search term - if any match
    - newest_articles: A list of the 5 most recently created KBEntry objects.
    - top_rated_articles: A list of the 5 highest-rated KBEntry objects.
    - search_term: The search term entered by the user, if any.
    """
    search_term = request.GET.get("search", None)
    articles = KBEntry.objects.none()  # Default to no entries
    
    # Check if search parameter is present in the request
    if search_term is not None:
        search_term = search_term.strip()
        if search_term:
             # Get all articles
            all_articles = KBEntry.objects.filter(
                deleted_datetime__isnull=True
            )

            # Filter articles based on the search term, but exclude HTML tags
            # As search was bringing back articles with a search like qwe - this might have been included in an image
            articles = [
                article for article in all_articles
                if search_term.lower() in strip_tags(article.article).lower() # match if in article after stripping tags
                or search_term.lower() in article.title.lower() # match if in article title
                or any(search_term.lower() in tag.name.lower() for tag in article.meta_data.all()) # match if in any tags
                or search_term.lower() in article.created_by.username.lower() #match on username
            ]
            for article in articles:
                article.article = strip_tags(article.article.replace("<p>", " ")) # strip tags, as we want to display without in a table
        else:
            # Code for handling an empty search term (showing all articles)
            articles = KBEntry.objects.filter(deleted_datetime__isnull=True)
            for article in articles:
                article.article = strip_tags(article.article.replace("<p>", " ")) 
       
    # If search results return less than 5 articles or no search termy:
    if len(articles) < 5 or not search_term:
        newest_articles = KBEntry.objects.filter(
            deleted_datetime__isnull=True
        ).order_by("-created_datetime")[:5]
        # Ordered by rating
        top_rated_articles = KBEntry.objects.filter(
            deleted_datetime__isnull=True
        ).order_by("-rating")[:5]
    else:
        newest_articles = []
        top_rated_articles = []

    # This is what we return to the template
    context = {
        "articles": articles, # The articles with tags stripped from article.article
        "newest_articles": newest_articles, # top 5 newest articles
        "top_rated_articles": top_rated_articles, # top 5 rated articles
        "search_term": search_term if search_term is not None else "", # the original search term
    }

    return render(request, "knowledge/home.html", context)

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
    all_tags = Tag.objects.all().values_list(
        "name", flat=True
    )  # Fetch all available tags

    if request.method == "POST":
        form = KBEntryForm(request.POST, request=request)
        if form.is_valid():
            article = form.save(
                commit=False
            )  # Temporarily save without committing to DB
            article.last_modified_by = None
            article.save()  # Save the KBEntry instance to the database
            # Create an Audit Entry for the Newly Created Article
            Audit(
                user=request.user,
                kb_entry=article,
                action_details=f"Created a new article: '{article.title[:50]}'",
            ).save()

            # Process tags
            tag_names = request.POST.get("meta_data", "").split(",")
            for tag_name in tag_names:
                # sanitize tags
                tag_name = sanitize_tag(tag_name.strip())  # Sanitize input
                # only add valid tags invalid tags are ignored
                if is_valid_tag(tag_name):
                    tag, created = Tag.objects.get_or_create(name=tag_name)
                    article.meta_data.add(tag)
                
                
            messages.success(
                request, "Your knowledge base entry was successfully created!"
            )

            # Redirect to the article_detail view for the newly created article
            return redirect(
                f"/article/{article.id}"
            )  # The URL pattern for article_detail is '/article/?id=ARTICLE_ID'

        else:
            messages.error(request, "Please correct the error above.")
    else:
        form = KBEntryForm(request=request)
    jsontags = json.dumps(list(all_tags))
    context = {
        "form": form,
        "all_tags_json": json.dumps(
            list(all_tags)
        ),  # Serialize all_tags to JSON for the template
    }
    return render(request, "knowledge/create.html", context)

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
        messages.error(request, "Article not found or has been deleted.")
        return redirect("home")

    user_has_upvoted = request.user in article.upvotes.all()
    user_has_downvoted = request.user in article.downvotes.all()

    context = {
        "article": article,
        "user_has_upvoted": user_has_upvoted,
        "user_has_downvoted": user_has_downvoted,
        "is_deleted": article.deleted_datetime
        is not None,  # Indicates if the article is deleted
    }

    return render(request, "knowledge/article_detail.html", context)

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

    all_tags = Tag.objects.all().values_list(
        "name", flat=True
    ) 

    # Fetch the article instance using the article_id
    try:
        article = KBEntry.objects.get(pk=article_id)
        associated_metatags = article.meta_data.all()
    except KBEntry.DoesNotExist:
        messages.error(request, "No article exists with this ID")
        return redirect("home")

    # Check if user is authorized to edit (superuser or article author)
    if not (request.user.is_superuser or article.created_by == request.user):
        messages.error(request, "You are not authorized to edit this article.")
        return redirect(
            f"/article/{article_id}/"
        )  # Redirect to article detail

    # If article is deleted and user is not superuser
    if article.deleted_datetime and article.created_by == request.user:
        messages.error(request, "You can't edit this article - it has been deleted.")
        return redirect("home")  # Redirect to article detail
    
    if request.method == "POST":
        form = KBEntryForm(request.POST, instance=article, request=request)
        if form.is_valid():
            form.save()
            article.last_modified_by = request.user
            article.modified_datetime = timezone.now()
            article.save()
            # Create an Audit record : Article Editted
            Audit(
                user=request.user,
                kb_entry=article,
                action_details=f"Editted Article : '{article.title[:50]}'",
            ).save()
            article.meta_data.clear()
            # Process tags
            tag_names = request.POST.get("meta_data", "").split(",")
            for tag_name in tag_names:
                tag_name = sanitize_tag(tag_name.strip())  # Sanitize input
                if is_valid_tag(tag_name):  # Validate tag
                    tag, created = Tag.objects.get_or_create(name=tag_name)
                    article.meta_data.add(tag)

            # Redirect to the updated article or some success page
            return redirect(f"/article/{article_id}/")

    else:
        form = KBEntryForm(instance=article, request=request)

    context = {
        "form": form,
        "article": article,
        "associated_metatags": [tag.name for tag in associated_metatags],
        "is_deleted": article.deleted_datetime,
        "all_tags_json": json.dumps(list(all_tags)),  # Serialize all_tags to JSON here
    }
    return render(request, "knowledge/edit_article.html", context)

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

    return render(request, "knowledge/all_articles.html", {"articles": articles})

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
    user_articles = KBEntry.objects.filter(
        created_by=request.user, deleted_datetime__isnull=True
    )
    return render(request, "knowledge/my_articles.html", {"articles": user_articles})

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
        user_articles = KBEntry.objects.filter(
            created_by=user_obj, deleted_datetime__isnull=True
        )

        # Render the template with the user's articles
        return render(
            request,
            "knowledge/user_articles.html",
            {"articles": user_articles, "author": user_obj},
        )
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect("home")

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
        article.downvotes.remove(
            request.user
        )  # remove downvote if user previously downvoted

        rating_info = calculate_rating(article)  # a function to calculate the rating
        article.rating = rating_info['rating']  # Saving the calculated rating to the article
        article.save()  # Committing the change to the database

        return JsonResponse({
            'success': True,
            **rating_info
        })
    except KBEntry.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Article not found"})

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
        article.downvotes.add(
            request.user
        )  # remove downvote if user previously downvoted

        rating_info = calculate_rating(article)  # a function to calculate the rating
        article.rating = rating_info['rating']  # Saving the calculated rating to the article
        article.save()  # Committing the change to the database

        return JsonResponse({"status": "success", **rating_info})
    except KBEntry.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Article not found"})

######################################### ----------- This is the end of normal Authenticated User Views ----------


######################################### ----------- The Views Below are restricted to 'superusers' ----------

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
        return redirect("home")

    # Fetch all audit logs
    audits = Audit.objects.all().order_by(
        "-action_datetime"
    )  # Most recent actions first

    context = {"audits": audits}

    return render(request, "knowledge/audit_logs.html", context)

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
        return redirect("home")
    
    users = User.objects.all()  # get all users
    return render(request, "knowledge/user_list.html", {"users": users})

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
        return redirect("home")

    # Get the user by ID
    try:
        user_to_toggle = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect("user-list")

    # Check if the user to toggle is the same as the logged-in superuser
    if user_to_toggle == request.user:
        messages.error(request, "You cannot deactivate your own account!")
        return redirect("user-list")

    # Toggle the user's active status
    user_to_toggle.is_active = not user_to_toggle.is_active
    user_to_toggle.save()

    # Provide feedback to the superuser
    if user_to_toggle.is_active:
        messages.success(
            request, f"{user_to_toggle.username}'s account has been activated."
        )
    else:
        messages.success(
            request, f"{user_to_toggle.username}'s account has been deactivated."
        )
    return redirect("user-list")

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
        return redirect("home")
    
    try:
        article = KBEntry.objects.get(pk=article_id)
    except KBEntry.DoesNotExist:
        messages.error(request, "Article not found.")
        return redirect("home")  

    if request.method == "POST":
        softDeleteArticle(article, request.user)
        Audit(
            user=request.user,
            kb_entry=article,
            action_details=f"Soft deleted article: '{article.title[:50]}'",
        ).save()

        messages.success(request, "Article successfully deleted.")
        return redirect("article_detail", article_id=article.id)

    return render(request, "knowledge/confirm_delete.html", {"article": article})

@login_required
def quick_delete_toggle(request, article_id):
    """ 
    Handles the soft deletion and undeletion (toggle) of an article from the All Article View

    - Accessible only to authenticated users due to the @login_required decorator.
    - Checks if the user is a superuser:
        - If not, the user is redirected to the home page with an error message.
    - If the user is a superuser:
        - Attempts to fetch the KBEntry object that corresponds to the provided article_id parameter.
        - If the KBEntry object is not found, an error message is displayed, and the user is redirected to the home page.
        - If the KBEntry object is found:
        - If the article is delete
            - Uses the undeleteArticle function
        - Else
            - Uses the softDeslete function
        - Creates an Audit entry to log the deletion action.
        - Displays a success message and redirects the user to the article detail page.

    Parameters:
    - request (HttpRequest): The HTTP request object, which contains information about the current user.
    - article_id (int): The ID of the article to be deleted.

    Returns:
    - HttpResponse: Keeps user on the All Articles Page
    """
    if not request.user.is_superuser:
        messages.error(request, "You don't have permission to perform this action.")
        return JsonResponse({'success': False, 'message': "Unauthorized"})

    try:
        article = KBEntry.objects.get(pk=article_id)
    except KBEntry.DoesNotExist:
        messages.error(request, "Article not found.")
        return JsonResponse({'success': False, 'message': "Article not found"})

    if article.deleted_datetime:
        # If article is already deleted, undelete it
        undeleteArticle(article)
        action_details = f"Undeleted article: '{article.title[:50]}'"
        action = "undeleted"
    else:
        # Soft delete the article
        softDeleteArticle(article, request.user)
        action_details = f"Soft deleted article: '{article.title[:50]}'"
        action = "deleted"

    Audit(
        user=request.user,
        kb_entry=article,
        action_details=action_details,
    ).save()

    #messages.success(request, "Article successfully " + action + ".")
    return JsonResponse({'success': True, 'action': action})

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
        messages.error(request, "You do not have permission to undelete articles.")
        return redirect("home")

    # Check if the article is already undeleted
    if article.deleted_datetime is None:
        messages.info(request, "This article is not deleted.")
        return redirect("article_detail", article_id=article.id)

    # Handle the POST request to confirm undeletion
    if request.method == "POST":
        article.deleted_datetime = None
        article.save()
        # Add the audit entry for undeletion
        Audit(
            user=request.user,
            kb_entry=article,
            action_details=f"Undeleted article: '{article.title[:50]}'",
        ).save()

        messages.success(request, "The article has been successfully undeleted.")
        return redirect("article_detail", article_id=article.id)

    # Render the confirmation template for undeletion
    return render(request, "knowledge/confirm_undelete.html", {"article": article})

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
            messages.error(
                request, "You are not allowed to permanently delete any articles"
            )
            return redirect("home")
        return render(
            request, "knowledge/confirm_permanent_delete.html", {"article": article}
        )
    except KBEntry.DoesNotExist:
        messages.error(request, "Article not found.")
        return redirect("home")

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
            messages.error(
                request, "You are not allowed to permanently delete any articles"
            )
            return redirect("home")

        # Create a new audit log entry noting the permanent deletion BEFORE deleting the article
        Audit(
            user=request.user,
            action_details=f"Permanently deleted article: {article.title[:50]}",
        ).save()

        # Now, delete the article
        article.delete()

        messages.success(request, "Article was permanently deleted.")
    except KBEntry.DoesNotExist:
        messages.error(request, "Article not found.")

    return redirect("home")

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
        messages.error(request, "You are not allowed to manage Tags")
        return redirect("home")
    
    if request.method == "POST":
        tag_id_to_delete = request.POST.get("tag_id")
        if tag_id_to_delete:
            Tag.objects.filter(id=tag_id_to_delete).delete()
            return redirect("manage_tags")

    # Fetch all tags, annotate them with the number of times they are used,
    # and order them by this count in descending order
    tags = Tag.objects.annotate(num_times_used=models.Count("kbentry")).order_by(
        "-num_times_used"
    )

    context = {"tags": tags}
    return render(request, "knowledge/manage_tags.html", context)

###################################### --------------- End of SuperUser Views ------------------