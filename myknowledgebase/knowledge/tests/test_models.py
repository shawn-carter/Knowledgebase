# knowledge/tests/test_models.py

from django.contrib.auth.models import User
from .base_tests import BaseTestCaseWithUser
from knowledge.models import KBEntry, Audit, Tag
from knowledge.models import calculate_rating

class KBEntryModelTestCase(BaseTestCaseWithUser):
    def test_article_creation(self):
        # Since we're logged in as testuser, use this user for the created_by field
        article = KBEntry.objects.create(title="Test Article", article="This is a test article.", created_by=self.user)
        
        self.assertEqual(article.title, "Test Article")
        self.assertEqual(article.article, "This is a test article.")
        self.assertEqual(article.created_by, self.user)

class AuditModelTestCase(BaseTestCaseWithUser):
    def test_audit_creation(self):
        article = KBEntry.objects.create(title="Test Article", article="This is a test article", created_by=self.user)
        audit = Audit.objects.create(user=self.user, kb_entry=article, action_details="Created an article")
        
        self.assertEqual(audit.kb_entry, article)
        self.assertEqual(audit.user, self.user)
        self.assertEqual(audit.action_details, "Created an article")

class TagModelTestCase(BaseTestCaseWithUser):
    def test_tag_creation(self):
        tag = Tag.objects.create(name="TestTag")
        self.assertEqual(tag.name, "TestTag")
        
    def test_tag_association_with_article(self):
        tag = Tag.objects.create(name="TestTag")
        article = KBEntry.objects.create(title="Test Article", article="This is a test article", created_by=self.user)
        article.meta_data.add(tag)
        
        self.assertIn(tag, article.meta_data.all())

class KBEntryUpvoteTestCase(BaseTestCaseWithUser):
    def test_upvote_functionality(self):
        article = KBEntry.objects.create(title="Test Article", article="This is a test article", created_by=self.user)
        
        initial_rating = article.rating
        article.upvotes.add(self.user)
        article.rating = calculate_rating(article)
        article.save()
        
        self.assertEqual(article.rating, 100)
        
class KBEntryDownvoteTestCase(BaseTestCaseWithUser):
    def test_downvote_functionality(self):
        article = KBEntry.objects.create(title="Test Article", article="This is a test article", created_by=self.user)
        
        article.downvotes.add(self.user)
        article.rating = calculate_rating(article)
        article.save()
        
        # Assuming the initial rating was 0, and after one downvote it becomes 0 again
        self.assertEqual(article.rating, 0)