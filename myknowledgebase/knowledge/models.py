from django.db import models
from django.contrib.auth.models import User

class KBEntry(models.Model):
    title = models.CharField(max_length=255)
    article = models.TextField()
    created_by = models.ForeignKey(User, related_name="created_kb_entries", on_delete=models.SET_NULL, null=True)
    created_datetime = models.DateTimeField(auto_now_add=True)
    modified_datetime = models.DateTimeField(auto_now=True)
    last_modified_by = models.ForeignKey(User, related_name="modified_kb_entries", on_delete=models.SET_NULL, null=True)
    deleted_datetime = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(User, related_name="deleted_kb_entries", on_delete=models.SET_NULL, null=True, blank=True)
    upvotes = models.ManyToManyField(User, related_name="upvoted_kb_entries", blank=True)
    downvotes = models.ManyToManyField(User, related_name="downvoted_kb_entries", blank=True)
    meta_data = models.ManyToManyField('Tag', blank=True) # Assuming you will have a 'Tag' model

class Tag(models.Model):
    name = models.CharField(max_length=100)

class Audit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action_datetime = models.DateTimeField(auto_now_add=True)
    kb_entry = models.ForeignKey(KBEntry, on_delete=models.CASCADE)
    action_details = models.CharField(max_length=255)