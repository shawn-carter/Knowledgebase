# knowledge/tests/test_views.py

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from knowledge.models import KBEntry
from .base_tests import BaseTestCaseWithUser
from .base_tests import BaseTestCaseWithSuperUser

class AuthenticatedUserRedirectTest(TestCase):
    """
    These Tests are to ensure that Authenticated Users are redirected to the home page
    on pages that are meant for Non Authenticated Users

    """
    def setUp(self):
        # First we create a test user and login with that user
        self.username = 'testuser'
        self.password = 'testpass123'
        self.user = User.objects.create_user(self.username, password=self.password)
        self.client.login(username=self.username, password=self.password)
    
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
        # Here user_id and token are dummy values as we are only testing the redirect for authenticated users
        response = self.client.get(reverse('password_reset_confirm', args=[1, 'token']))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))
        
    def test_password_reset_complete_view_redirect_authenticated_user(self):
        response = self.client.get(reverse('password_reset_complete'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))

class NonAuthenticatedUserRedirectTest(TestCase):
    """
    These tests are to ensure that Non Authenticated Users cannot reach any pages
    that are intended for Authenticated Users
    """
    def test_home_redirect(self):
        response = self.client.get(reverse('home'))
        self.assertRedirects(response, '/login/?next=' + reverse('home'))
        
    def test_change_password_redirect(self):
        response = self.client.get(reverse('change_password'))
        self.assertRedirects(response, '/login/?next=' + reverse('change_password'))
        
    def test_create_redirect(self):
        response = self.client.get(reverse('create'))
        self.assertRedirects(response, '/login/?next=' + reverse('create'))
        
    def test_article_detail_redirect(self):
        response = self.client.get(reverse('article_detail', args=[1]))
        self.assertRedirects(response, '/login/?next=' + reverse('article_detail', args=[1]))
        
    def test_edit_article_redirect(self):
        response = self.client.get(reverse('edit_article', args=[1]))
        self.assertRedirects(response, '/login/?next=' + reverse('edit_article', args=[1]))
        
    def test_all_articles_redirect(self):
        response = self.client.get(reverse('allarticles'))
        self.assertRedirects(response, '/login/?next=' + reverse('allarticles'))
        
    def test_my_articles_redirect(self):
        response = self.client.get(reverse('my_articles'))
        self.assertRedirects(response, '/login/?next=' + reverse('my_articles'))
        
    def test_user_articles_redirect(self):
        response = self.client.get(reverse('user_articles', args=[1]))
        self.assertRedirects(response, '/login/?next=' + reverse('user_articles', args=[1]))
        
    def test_upvote_article_redirect(self):
        response = self.client.get(reverse('upvote_article', args=[1]))
        self.assertRedirects(response, '/login/?next=' + reverse('upvote_article', args=[1]))
        
    def test_downvote_article_redirect(self):
        response = self.client.get(reverse('downvote_article', args=[1]))
        self.assertRedirects(response, '/login/?next=' + reverse('downvote_article', args=[1]))
        
    def test_logout_redirect(self):
        response = self.client.get(reverse('logout'))
        self.assertRedirects(response, '/login/?next=' + reverse('logout'))

class AuthenticatedUserAccessTest(TestCase):
    
    def setUp(self):
        # Create a test user and log in
        self.username = 'testuser'
        self.password = 'testpass123'
        self.user = User.objects.create_user(username=self.username, password=self.password)
        self.client.login(username=self.username, password=self.password)
        # Create a test article
        self.article = KBEntry.objects.create(title='Test Article', article='Test Content', created_by=self.user)
    
    def test_home(self):
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)
        
    def test_change_password(self):
        response = self.client.get(reverse('change_password'))
        self.assertEqual(response.status_code, 200)
        
    def test_create(self):
        response = self.client.get(reverse('create'))
        self.assertEqual(response.status_code, 200)
        
    def test_article_detail(self):
        response = self.client.get(reverse('article_detail', args=[self.article.id]))
        self.assertEqual(response.status_code, 200)
        
    def test_edit_article(self):
        response = self.client.get(reverse('edit_article', args=[self.article.id]))
        self.assertEqual(response.status_code, 200)
        
    def test_all_articles(self):
        response = self.client.get(reverse('allarticles'))
        self.assertEqual(response.status_code, 200)
        
    def test_my_articles(self):
        response = self.client.get(reverse('my_articles'))
        self.assertEqual(response.status_code, 200)
        
    def test_user_articles(self):
        response = self.client.get(reverse('user_articles', args=[1]))
        self.assertEqual(response.status_code, 200)
        
    def test_upvote_article(self):
        response = self.client.get(reverse('upvote_article', args=[1]))
        self.assertEqual(response.status_code, 200)
        
    def test_downvote_article(self):
        response = self.client.get(reverse('downvote_article', args=[1]))
        self.assertEqual(response.status_code, 200)
        
    def test_logout(self):
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('login'))  # Check the redirect URL

class LoginViewTestCase(TestCase):
    
    def setUp(self):
        self.username = 'john'
        self.password = 'password'
        self.user = User.objects.create_user(username=self.username, password=self.password)
    
    def test_view_uses_correct_template(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/login.html')
        
    def test_login_with_correct_credentials(self):
        response = self.client.post(reverse('login'), data={
            'username': self.username,
            'password': self.password,
        })
        # Should redirect to the 'home' page
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))
        
    def test_login_with_incorrect_credentials(self):
        response = self.client.post(reverse('login'), data={
            'username': self.username,
            'password': 'wrong_password',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid username or password.")
        
    def test_authenticated_user_redirect(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 302)  # Expect a redirect
        self.assertRedirects(response, reverse('home'))

class KBEntryViewTestCase(BaseTestCaseWithUser):
    
    def setUp(self):
        super().setUp()  # This will run the setUp from BaseTestCaseWithUser
        # Create a sample article
        self.article = KBEntry.objects.create(
            title='Sample Article',
            article='This is a sample article for testing.',
            created_by=self.user  # Use the user created in BaseTestCaseWithUser
        )

    def test_article_detail_view(self):
        """Test the article detail view."""
        response = self.client.get(reverse('article_detail', args=[self.article.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Sample Article')
        
class RegisterViewTestCase(TestCase):
    
    def test_view_uses_correct_template(self):
        response = self.client.get(reverse('register'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/register.html')
        
    def test_register_new_user(self):
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
    
    def setUp(self):
        self.email = 'user@example.com'
        self.user = User.objects.create_user(username='user', email=self.email, password='password')
    
    def test_view_uses_correct_template(self):
        response = self.client.get(reverse('password_reset_request'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/password_reset_request.html')
        
    def test_password_reset_for_existing_user(self):
        response = self.client.post(reverse('password_reset_request'), data={'email': self.email})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'knowledge/password_reset_link.html')
        
    def test_password_reset_for_non_existing_user(self):
        response = self.client.post(reverse('password_reset_request'), data={'email': 'nonexistent@example.com'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'No account with this email address exists.')

class SuperUserViewsTest(BaseTestCaseWithSuperUser):
    
    def test_superuser_urls(self):
        # List of URLs to be tested
        # For URLs with dynamic parts, like <int:article_id>, you should replace them with actual values from your test data
        urls = [
            reverse('audit_logs'),
            reverse('user-list'),
            reverse('toggle_user_active_status', args=[1]),  # replace 1 with actual user_id
            reverse('delete_article', args=[self.article.id]),  # replace 1 with actual article_id
            reverse('undelete_article', args=[self.article.id]),  # replace 1 with actual article_id
            reverse('confirm_permanent_delete', args=[self.article.id]),
            reverse('perform_permanent_delete', args=[self.article.id]),
            reverse('manage_tags')
        ]
        
        # Iterate over the list of URLs and run the checks for each one
        for url in urls:
            self.check_url_for_different_user_types(url)  