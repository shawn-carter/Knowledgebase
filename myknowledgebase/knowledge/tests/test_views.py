# knowledge/tests/test_views.py

from base64 import urlsafe_b64encode
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.contrib.messages import get_messages
from knowledge.models import KBEntry
from .base_tests import BaseTestCaseWithUser, BaseTestCaseWithSuperUser
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.test import TestCase, tag

token_generator = PasswordResetTokenGenerator()

class NonAuthenticatedUserAccessTest(TestCase):
    """
    Tests ensuring that non authenticated users can access the following
    urls: login, register, reset_password, password_reset_request, password_reset_confirm, password_reset_complete
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

    def test_password_reset_request_view(self):
        response = self.client.get(reverse('password_reset_confirm', args=[1,'token']))
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
        self.assertEqual(response.status_code, 302)  # Expect a redirect
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
        # 'token' is required
        response = self.client.get(reverse('password_reset_confirm', args=[1, 'token']))
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
    """
    def setUp(self):
        self.username = 'shawncarter'
        self.password = 'g0oDp4$$w0rd'
        self.user = User.objects.create_user(username=self.username, password=self.password)
    
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
        # Should redirect to the 'home' page
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))
        
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

    
class ArticleViewTestCase(BaseTestCaseWithUser):
    """
    This Test creates a Test Article, and makes sure it can be returned
    It also checks what happens if a user attempts to access article_details for a
    non existing article
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
        self.assertRedirects(response, reverse('home'))
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
        response = self.client.post(reverse('password_reset_request'), data={'email': self.email})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/password_reset_link.html')        

class PasswordResetIntegrationTest(TestCase):
    """ 
    This test goes further than the previous test
    It tests the password reset process for a new user
    """
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='old_password')
        self.email = 'test@example.com'
    
    @tag('integration') #tagged during debug to allow quicker testing   
    def test_password_reset_flow(self):
        # Check that the user cannot log in with a new password
        self.assertFalse(self.client.login(username=self.user.username, password='new_password_123'))
        
        # Request password reset
        response = self.client.post(reverse('password_reset_request'), data={'email': self.email})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/password_reset_link.html')
        
        # Generate password reset link
        user = User.objects.get(email=self.email)
        token = token_generator.make_token(user)
        reset_url = reverse("password_reset_confirm", args=[user.pk, token])
        
        # Reset password
        new_password = 'new_password_123'
        response = self.client.post(reset_url, data={
            'new_password1': new_password, 
            'new_password2': new_password
        })
        
        # Check that the response redirects to the password reset complete page
        self.assertRedirects(response, reverse('password_reset_complete'))
        
        # Confirm that the password reset was successful by checking the user can login
        self.assertTrue(self.client.login(username=self.user.username, password=new_password))

class DeleteViewTestCase(BaseTestCaseWithUser):
          
    def test_delete_non_existent_article(self):
        # Attempt to delete an article with an ID that doesn't exist in the database
        non_existent_article_id = 99999  # Assuming this ID doesn't exist
        response = self.client.get(reverse("delete_article", args=[non_existent_article_id]))
        
        # Assert that the user is redirected to the 'home' page
        self.assertRedirects(response, reverse('home'))
        
        # Check for the error message
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "You don't have permission to view this page.")


class ConfirmDeleteViewTestCase(BaseTestCaseWithUser):
           
    def test_permanent_delete_non_existent_article(self):
        # Attempt to permanently delete an article with an ID that doesn't exist in the database
        non_existent_article_id = 61  # Assuming this ID doesn't exist
        response = self.client.get(reverse("confirm_permanent_delete", args=[non_existent_article_id]))
        
        # Assert that the user is redirected to the 'home' page
        self.assertRedirects(response, reverse('home'))
        
        # Check for the error message
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "Article not found.")

        
