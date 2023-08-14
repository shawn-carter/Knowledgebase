from django.test import TestCase, Client
from django.contrib.auth.models import User

# Class to be used with functions that need a user to be logged in
class BaseTestCaseWithUser(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.client.login(username='testuser', password='testpass')

# Class to be used with functions that require superuser priviledges
class BaseTestCaseWithSuperUser(BaseTestCaseWithUser):
    def setUp(self):
        super().setUp()
        self.superuser = User.objects.create_superuser(username='testadmin', password='adminpass')
        self.client.login(username='testadmin', password='adminpass')
