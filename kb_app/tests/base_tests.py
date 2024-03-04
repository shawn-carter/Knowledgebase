from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from kb_app.models import KBEntry
from django.utils import timezone

# Class to be used with functions that need a user to be logged in
class BaseTestCaseWithUser(TestCase):
    """ 
    This class can be used for Test cases that use a regular user
    It creates a user and then creates an article for that user
    """
    def setUp(self):
        self.client = Client()
        self.email = "shawn.carter@redcar-cleveland.gov.uk"  # Needs a valid email address (or Azure email client fails)
        self.user = User.objects.create_user(
            username="testuser", password="testpass", email=self.email
        )
        self.client.login(username="testuser", password="testpass")
        self.article = KBEntry.objects.create(
            title="Test Article", article="Test Content", created_by=self.user
        )


class BaseTestCaseWithSuperUser(BaseTestCaseWithUser):
    """ 
    This class can be used for Test cases that require a superuser
    It creates a superuser and an article for that user
    """
    def setUp(self):
        super().setUp()
        self.superuser = User.objects.create_superuser(
            username="testadmin", password="adminpass", email=self.email  # Include the email address here
        )
        self.client.login(username="testadmin", password="adminpass")
        self.article = KBEntry.objects.create(
            title="Test Article",
            article="This is a test article",
            created_by=self.superuser,
        )

    def check_url_for_different_user_types(self, url):
        """ 
        This function logs the superuser in and checks access to the url that is passed into the function
        It then logs the normal user in and checks if they can access it
        Finally logging the user out to see if unauthenticated users can access the url
        """
        
        # Check for superuser

        # We expect the following pages to redirect (even for superuser) because they do some action and return the user
        # to the home page or the article page once deleted/undeleted.
        redirect_pages_for_superuser = [
            reverse("perform_permanent_delete", args=[1]),
            reverse("confirm_permanent_delete", args=[1]),
            reverse("toggle_user_active_status", args=[1]),
            reverse("undelete_article", args=[1])
        ]

        self.client.login(username="testadmin", password="adminpass")
        response = self.client.get(url)

        if url in redirect_pages_for_superuser:
            try:
                self.assertEqual(
                    response.status_code, 302
                )  # Expecting a redirect after performing an action
            except AssertionError:
                print(f"AssertionError for URL: {url} for superuser")
                raise
        else:
            try:
                self.assertEqual(
                    response.status_code, 200
                )  # Expecting a successful response, since this is a rendered page
            except AssertionError:
                print(f"AssertionError for URL: {url} for superuser")
                raise

        # Check for normal authenticated users
        # If a normal user attempts to access a superuser url we expect them to be redirected to home (/)
        self.client.login(username="testuser", password="testpass")
        response = self.client.get(url)
        try:
            self.assertEqual(response.status_code, 302)  # Expecting a redirect to 'home'
        except AssertionError:
            # If authenticated user is able to access the url - we raise Assertion Error with the url
            print(f"AssertionError for URL: {url} for authenticated user")
            raise

        # Check for unauthenticated users
        # If a non authenticated user attempts to access a superuser url we expect them to be redirected to /login/
        self.client.logout()
        response = self.client.get(url)
        try:
            self.assertRedirects(response, f'{reverse("login")}?next={url}')  # Expecting a redirect to 'login'
        except AssertionError:
            # If non authenticated user is able to access the url - we raise Assertion Error with the url
            print(f"AssertionError for URL: {url} for non authenticated user")
            raise
