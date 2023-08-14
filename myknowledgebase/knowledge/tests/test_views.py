# knowledge/tests/test_views.py

from django.urls import reverse
from knowledge.models import KBEntry
from .base_tests import BaseTestCaseWithUser  # Import the base test case

class KBEntryViewTestCase(BaseTestCaseWithUser):  # Inherit from BaseTestCaseWithUser
    
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