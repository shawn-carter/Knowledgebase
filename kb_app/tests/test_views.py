# knowledge/tests/test_views.py

from .base_tests import BaseTestCaseWithUser, BaseTestCaseWithSuperUser
from base64 import urlsafe_b64encode
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.messages import get_messages
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ObjectDoesNotExist
from django.test import TestCase, tag
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from kb_app.models import KBEntry
from unittest import skip
from unittest.mock import patch
from django.utils.dateparse import parse_datetime
from django.utils.timezone import now

token_generator = PasswordResetTokenGenerator()

def add_session_to_request(request):
    """Middleware to add session to requests made in test cases."""
    middleware = SessionMiddleware()
    middleware.process_request(request)
    request.session.save()

# These are standard tests to ensure users can access URLS that they should be able to

class NonAuthenticatedUserAccessTest(TestCase):
    """
    Tests ensuring that non authenticated users can access the following
    urls: login, register, reset_password, password_reset_request, password_reset_confirm, password_reset_complete
    We expect the response to be 200 (OK)
    """
    def test_login_view(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        
    def test_register_view(self):
        response = self.client.get(reverse('register'))
        self.assertEqual(response.status_code, 200)
    
    def test_password_reset_request_view(self):
        response = self.client.get(reverse('password_reset_request'))
        self.assertEqual(response.status_code, 200)

    def test_password_reset_confirm_view(self):
        uidb64 = urlsafe_base64_encode(force_bytes(1))
        response = self.client.get(reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': 'mock token'}))
        self.assertEqual(response.status_code, 200)

    def test_password_reset_complete_view(self):
        response = self.client.get(reverse('password_reset_complete'))
        self.assertEqual(response.status_code, 200)

class NonAuthenticatedUserRedirectTest(TestCase):
    """
    These tests are to ensure that Non Authenticated Users cannot reach any pages are 
    that are intended for Authenticated Users or Super Users and the user is redirected to /login/?next=url 
        
    authenticated user urls: home, change_password, create, article_detail, edit_article, allarticles, my articles,
    user_articles, upvote_article, downvote article and logout
    
    super user urls: audit_logs, user-list, toggle_user_active_status, delete_article, undelete_article,
    confirm_permanent_delete, manage_tags
    """
    # These views are for authenticated users
    
    def test_home_redirect(self):
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('home'))
        
    def test_change_password_redirect(self):
        response = self.client.get(reverse('change_password'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('change_password'))
        
    def test_create_redirect(self):
        response = self.client.get(reverse('create'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('create'))
        
    def test_article_detail_redirect(self):
        response = self.client.get(reverse('article_detail', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('article_detail', args=[1]))
        
    def test_edit_article_redirect(self):
        response = self.client.get(reverse('edit_article', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('edit_article', args=[1]))
        
    def test_all_articles_redirect(self):
        response = self.client.get(reverse('allarticles'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('allarticles'))
        
    def test_my_articles_redirect(self):
        response = self.client.get(reverse('my_articles'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('my_articles'))
        
    def test_user_articles_redirect(self):
        response = self.client.get(reverse('user_articles', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('user_articles', args=[1]))
        
    def test_upvote_article_redirect(self):
        response = self.client.get(reverse('upvote_article', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('upvote_article', args=[1]))
        
    def test_downvote_article_redirect(self):
        response = self.client.get(reverse('downvote_article', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('downvote_article', args=[1]))
        
    def test_logout_redirect(self):
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('logout'))
    

    # These views are for super users
    def test_audit_logs_view_redirect(self):
        response = self.client.get(reverse('audit_logs'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('audit_logs'))  
        
    def test_user_list_redirect(self):
        response = self.client.get(reverse('user-list'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('user-list')) 
        
    def test_toggle_user_active_status_view_redirect(self):
        response = self.client.get(reverse('toggle_user_active_status', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('toggle_user_active_status', args=[1])) 
    
    def test_delete_article_redirect(self):
        response = self.client.get(reverse('delete_article', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('delete_article', args=[1])) 
    
    def test_undelete_article_view_redirect(self):
        response = self.client.get(reverse('undelete_article', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('undelete_article', args=[1])) 
    
    def test_confirm_permanent_delete_view_redirect(self):
        response = self.client.get(reverse('confirm_permanent_delete', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('confirm_permanent_delete', args=[1])) 
    
    def test_perform_permanent_delete_view_redirect(self):
        response = self.client.get(reverse('perform_permanent_delete', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('perform_permanent_delete', args=[1])) 
    
    def test_manage_tags_view_redirect(self):
        response = self.client.get(reverse('manage_tags'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, '/login/?next=' + reverse('manage_tags'))   

class AuthenticatedUsersAccessTest(BaseTestCaseWithUser):
    """
    These tests are to ensure that Authenticated Users (including SuperUsers) can access all pages that are
    used in the Knowledgebase app (for normal users)
    """
    def test_home_view(self):
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)
        
    def test_change_password_view(self):
        response = self.client.get(reverse('change_password'))
        self.assertEqual(response.status_code, 200)
        
    def test_create_view(self):
        response = self.client.get(reverse('create'))
        self.assertEqual(response.status_code, 200)
        
    def test_article_detail_view(self):
        response = self.client.get(reverse('article_detail', args=[1]))
        self.assertEqual(response.status_code, 200)
        
    def test_edit_article_view(self):
        response = self.client.get(reverse('edit_article', args=[1]))
        self.assertEqual(response.status_code, 200)
        
    def test_all_articles_view(self):
        response = self.client.get(reverse('allarticles'))
        self.assertEqual(response.status_code, 200)
        
    def test_my_articles_view(self):
        response = self.client.get(reverse('my_articles'))
        self.assertEqual(response.status_code, 200)
        
    def test_user_articles_view(self):
        response = self.client.get(reverse('user_articles', args=[1]))
        self.assertEqual(response.status_code, 200)
        
    def test_upvote_article_view(self):
        response = self.client.get(reverse('upvote_article', args=[1]))
        self.assertEqual(response.status_code, 200)
        
    def test_downvote_article_view(self):
        response = self.client.get(reverse('downvote_article', args=[1]))
        self.assertEqual(response.status_code, 200)
        
    def test_logout_view(self):
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect after logging out to /login/
        self.assertRedirects(response, '/login/')

class AuthenticatedUserRedirectTest(BaseTestCaseWithUser):
    """
    These Tests are to ensure that Authenticated Users are redirected to their home page
    on pages that are meant for Non Authenticated Users or Super Users
    
    non authenticated user urls: login, register, password_reset_request, password_reset_confirm, password_reset_complete
    
    superuser urls: audit_logs, user-list, toggle_user_active_status, delete_article, undelete_article,
    confirm_permanent_delete, perform_permanent_delete, manage_tags
    """
    # These pages are for unauthenticated users
    def test_login_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
        
    def test_register_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('register'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
              
    def test_password_reset_request_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('password_reset_request'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
        
    def test_password_reset_confirm_view_redirect_authenticated_user(self):
        # Generate a valid uidb64 for the test user
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = 'dummy-token'  # Since the focus is on redirection, not token validation

        response = self.client.get(reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token}))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
        
    def test_password_reset_complete_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('password_reset_complete'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
    
    # These pages are for superusers
    def test_audit_logs_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('audit_logs'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))    
        
    def test_user_list_redirect_authenticated_user(self):
        response = self.client.get(reverse('user-list'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
        
    def test_toggle_user_active_status_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('toggle_user_active_status', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
    
    def test_delete_article_redirect_authenticated_user(self):
        response = self.client.get(reverse('delete_article', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
    
    def test_undelete_article_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('undelete_article', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
    
    def test_confirm_permanent_delete_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('confirm_permanent_delete', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
    
    def test_perform_permanent_delete_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('perform_permanent_delete', args=[1]))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
    
    def test_manage_tags_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('manage_tags'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))          

class SuperUserViewsTest(BaseTestCaseWithSuperUser):
    """
    Although some of these tests have already been completed individually - I wanted to use a list of urls
    and to test each of them against each user type
    """
    def test_superuser_urls(self):
        # List of URLs to be tested
        # For URLs with dynamic parts, like <int:article_id>, you should replace them with actual values from your test data
        urls = [
            reverse('audit_logs'),
            reverse('user-list'),
            reverse('toggle_user_active_status', args=[1]), 
            reverse('delete_article', args=[1]),  
            reverse('undelete_article', args=[1]),  
            reverse('confirm_permanent_delete', args=[1]),
            reverse('perform_permanent_delete', args=[1]),
            reverse('manage_tags')
        ]
        
        # Iterate over the list of URLs and run the checks for each one
        # This uses a function from base_tests.py 
        for url in urls:
            self.check_url_for_different_user_types(url)

class LoginViewTestCase(TestCase):
    """
    This uses a regular TestCase, as we want to check the correct template is returned for a non authorised user
    We also check for attempts to login with incorrect credentials, and while leaving the username or password blank
    Although some similar tests have been performed using forms or models, these specifically check the view
    and we are checking for the response, not valid form data.
    """
    def setUp(self):
        self.username = 'shawncarter'
        self.password = 'g0oDp4$$w0rd'
        self.email = 'shawn.carter@redcar-cleveland.gov.uk'
        self.user = User.objects.create_user(username=self.username, password=self.password, email=self.email)
    
    def test_view_uses_correct_template(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/login.html')
        
    def test_login_with_correct_credentials(self):
        # Test for successfull login - should redirect user to home
        response = self.client.post(reverse('login'), data={
            'username': self.username,
            'password': self.password,
        })
        # Should redirect to the 'mfa' page
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('mfa_view'))
        
    def test_login_with_incorrect_credentials(self):
        # Attempt to login with wrong password
        response = self.client.post(reverse('login'), data={
            'username': self.username,
            'password': 'wrong_password',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid username or password")
               
    def test_login_with_blank_username(self):
        # Attempt to login with blank username
        response = self.client.post(
            reverse("login"),
            data={
                "username": "",
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Username cannot be blank")

    def test_login_with_blank_password(self):
        # Attempt to login with blank password
        response = self.client.post(
            reverse("login"),
            data={
                "username": self.username,
                "password": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Password cannot be blank")

class MFAViewTestCase(TestCase):
    def setUp(self):
        # Setup common across tests
        self.user = get_user_model().objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        self._setup_mfa_session()

    def _setup_mfa_session(self):
        # Mock the session setup as performed by your login process
        session = self.client.session
        session['authenticated_user_id'] = self.user.id
        session['mfa_pin'] = '123456'
        session['mfa_created'] = timezone.now().isoformat()
        session.save()

    @patch('django.utils.timezone.now')
    def test_mfa_with_correct_pin(self, mock_now):
        # Mock timezone.now() to return a specific datetime
        mock_now.return_value = timezone.make_aware(timezone.datetime(2020, 1, 1, 12, 0, 0))
        
        # No changes are needed in the _setup_mfa_session for this mock to work correctly, 
        # but make sure that when you use timezone.now() in your views or models to handle logic,
        # this mocked return_value is used.

        # Act: Submit the correct PIN to the mfa_view
        response = self.client.post(reverse('mfa_view'), {'pin': '123456'}, follow=True)
        
        # Assert
        self.assertRedirects(response, reverse('home'), status_code=302, target_status_code=200)

    def test_mfa_with_incorrect_pin(self):
        self._setup_mfa_session()  # Prepare the session with MFA details
        
        # Act: Submit an incorrect PIN to the mfa_view
        response = self.client.post(reverse('mfa_view'), {'pin': 'wrongpin'}, follow=True)
        
        # Assert: Check the response for the error message
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid PIN. Please try again.")

    def test_mfa_with_three_incorrect_attempts(self):
        # Setup: Prepare the session with MFA details
        self._setup_mfa_session()

        # Act: Simulate three incorrect PIN submissions
        response = self.client.post(reverse('mfa_view'), {'pin': 'wrongpin'}, follow=False)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid PIN. Please try again.")
        
        response = self.client.post(reverse('mfa_view'), {'pin': 'wrongpin'}, follow=False)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid PIN. Please try again.")
        
        response = self.client.post(reverse('mfa_view'), {'pin': 'wrongpin'}, follow=False)         
        # Check for redirection to the login page after the fourth attempt
        self.assertEqual(response.status_code, 302)
        # Check we are redirected to login
        self.assertRedirects(response, reverse('login'))
        
        # Check if the session variables related to MFA are cleared after exceeding max attempts
        self.assertIsNone(self.client.session.get('mfa_attempts'), "MFA attempts should be cleared from session")
        self.assertIsNone(self.client.session.get('authenticated_user_id'), "User ID should be cleared from session")
        self.assertIsNone(self.client.session.get('mfa_created'), "MFA creation time should be cleared from session")

class ArticleViewTestCase(BaseTestCaseWithUser):
    """
    This Test creates a Test Article, and makes sure it can be returned
    It also checks what happens if a user attempts to access article_details for a
    non existing article - we are checking for Ok or redirect responses and error messages returned
    """
    def setUp(self):
        super().setUp()  #Create test user
        # Create a sample article
        self.article = KBEntry.objects.create(
            title='Test Article',
            article='This is a test article for testing.',
            created_by=self.user  # Use the user created in BaseTestCaseWithUser
        )

    def test_article_detail_view(self):
        # Test the article detail view - for success
        response = self.client.get(reverse('article_detail', args=[self.article.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Article')
    
    def test_article_detail_view_article_not_exist(self):
        # Test for article that doesn't exist
        response = self.client.get(reverse('article_detail', args=[99]))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), 'Article not found or has been deleted.')

class EditViewTestCaseUser(BaseTestCaseWithUser):
    """ 
    Testing editing from the view - expecting Ok or error messages
    """
    def test_edit_article_view(self):
        # Testing correct template is returned
        response = self.client.get(reverse('edit_article', args=[self.article.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Article')
    
    def test_edit_article_submit(self):
        # POST some changes to edit_article - check that the db reflects the changes we expect
        response = self.client.post(reverse('edit_article', args=[self.article.id]), data={
            'title': 'Edited Title',
            'article': 'This article has been edited'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('article_detail', args=[self.article.id]))
        self.article.refresh_from_db()
        self.assertEqual(self.article.title, 'Edited Title')
        self.assertEqual(self.article.article, 'This article has been edited')
      
    def test_edit_non_existent_article(self):
        # Attempt to edit an article with an ID that doesn't exist in the database
        non_existent_article_id = 99999  # Assuming this ID doesn't exist
        response = self.client.get(reverse("edit_article", args=[non_existent_article_id]))
        self.assertRedirects(response, reverse('home'))
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), 'No article exists with this ID')
       
class RegisterViewTestCase(TestCase):
    """
    Testing the User Registration View/Integration Test
    """
    def test_view_uses_correct_template(self):
        # Testing that the correct template is returned
        response = self.client.get(reverse('register'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/register.html')
        
    def test_register_new_user(self):
        # Test that user is able to register with valid details
        response = self.client.post(reverse('register'), data={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'SecureP@ss123',
            'password2': 'SecureP@ss123',
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('register_success'))
        self.assertTrue(User.objects.filter(username='newuser').exists())
        
    def test_register_with_taken_username(self):
        """
        Test user registration with an existing username
        This view uses the built in Django user validation with some extra validation rules for
        things like username with all numbers, containing @ and space
        """ 
        User.objects.create_user(username='existinguser', password='testpass')
        response = self.client.post(reverse('register'), data={
            'username': 'existinguser',
            'email': 'newuser@example.com',
            'password1': 'SecureP@ss123',
            'password2': 'SecureP@ss123',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unsuccessful registration. Invalid information.")
        
class PasswordResetRequestViewTestCase(TestCase):
    """
    This tests that the view uses the correct template, then if an unknown user is directed to the password_reset_link.html
    """  
    def test_view_uses_correct_template(self):
        response = self.client.get(reverse('password_reset_request'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/password_reset_request.html')
        
    def test_password_reset_for_non_existing_user(self):
        response = self.client.post(reverse('password_reset_request'), data={'email': 'nonexistent@example.com'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No account with this email address exists.')

class PasswordResetRequestViewExistingUser(BaseTestCaseWithUser):
    # Tests if registered user is redirected with a valid email address
    def test_password_reset_for_existing_user_logged_out(self):
        self.client.logout()
        response = self.client.post(reverse('password_reset_request'), data={'email': self.email}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/password_reset_done.html')        

class DeleteViewTestCase(BaseTestCaseWithUser):
    """
    Normal user attempts to soft delete
    - Normal users do not have permission to soft delete articles
    """
    def test_delete_non_existent_article(self):
        # Attempt to delete an article with an ID that doesn't exist in the database
        non_existent_article_id = 99999  # This ID doesn't exist
        response = self.client.get(reverse("delete_article", args=[non_existent_article_id]))
        
        # Assert that the user is redirected to the 'home' page
        self.assertRedirects(response, reverse('home'))
        
        # Check for the error message
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "You don't have permission to view this page.")

    def test_delete_article(self):
        # Attempt to delete an article with an ID that doesn't exist in the database
        existing_article_id = 1  # This ID should exist
        response = self.client.get(reverse("delete_article", args=[existing_article_id]))
        
        # Assert that the user is redirected to the 'home' page
        self.assertRedirects(response, reverse('home'))
        
        # Check for the error message
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "You don't have permission to view this page.")

class DeleteViewTestCaseSuperUser(BaseTestCaseWithSuperUser):
    """
    Superuser attempts to soft delete
    """
    def test_delete_non_existent_article(self):
        # Attempt to delete an article with an ID that doesn't exist in the database
        non_existent_article_id = 99999  # This ID doesn't exist
        response = self.client.get(reverse("delete_article", args=[non_existent_article_id]))
        
        # Assert that the user is redirected to the 'home' page
        self.assertRedirects(response, reverse('home'))
        
        # Check for the error message that is returned
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "Article not found.")

    def test_delete_article(self):
        # Attempt to delete an article with an ID that doesn't exist in the database
        existing_article_id = 1  # This ID should exist
        response = self.client.get(reverse("delete_article", args=[existing_article_id]))
        
        # Assert that the response is 200
        self.assertEqual(response.status_code, 200)

class ConfirmDeleteViewTestCase(BaseTestCaseWithUser):
    """
    Normal user attempt to permanently delete an article bypassing the confirmation
    """
    def test_permanent_delete_non_existent_article(self):
        # Attempt to permanently delete an article with an ID that doesn't exist in the database
        non_existent_article_id = 61  # Assuming this ID doesn't exist
        response = self.client.get(reverse("perform_permanent_delete", args=[non_existent_article_id]))
        
        # Assert that the user is redirected to the 'home' page
        self.assertRedirects(response, reverse('home'))
        
        # Check for the error message
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "Article not found.")

    def test_permanent_delete_article(self):
        # Attempt to permanently delete an article with an ID that doesn't exist in the database
        existing_article_id = 1  # Assuming this ID does exist
        response = self.client.get(reverse("perform_permanent_delete", args=[existing_article_id]))
        
        # Assert that the user is redirected to the 'home' page
        self.assertRedirects(response, reverse('home'))
        
        # Check for the error message
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "You are not allowed to permanently delete any articles")        

class PerformDeleteViewTestCaseSuperUser(BaseTestCaseWithSuperUser):
    """
    Test Superuser attempt to perform permanently delete an article
    """
    def test_permanent_delete_non_existent_article(self):
        # Attempt to permanently delete an article with an ID that doesn't exist in the database
        non_existent_article_id = 61  # Assuming this ID doesn't exist
        response = self.client.get(reverse("perform_permanent_delete", args=[non_existent_article_id]))
        
        # Assert that the user is redirected to the 'home' page
        self.assertRedirects(response, reverse('home'))
        
        # Check for the error message
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "Article not found.")

    def test_permanent_delete_existing_article(self):
        # Test for an existing article
        existing_article_id = self.article.id  # Using the article created in the setUp method
        
        # Soft-delete the article
        self.article.deleted_datetime = timezone.now()
        self.article.save()
        
        # Attempt to permanently delete the article
        response = self.client.get(reverse("perform_permanent_delete", args=[existing_article_id]))
        self.assertRedirects(response, reverse('home'))
        
        # Check if the article exists in the database
        try:
            self.article.refresh_from_db()
            self.fail("Article still exists in the database. Expected it to be deleted.")
        except ObjectDoesNotExist:
            pass  # This is what we expect if the article has been deleted
        