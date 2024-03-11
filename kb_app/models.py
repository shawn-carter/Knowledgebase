from django.db import models
from django.contrib.auth.models import User

class KBEntry(models.Model):
    """
    Represents an entry in the knowledge base.

    Attributes:
    - title (CharField): The title of the knowledge base entry. Maximum length of 255 characters.
    - article (TextField): The main content of the knowledge base entry.
    - created_by (ForeignKey): The user who created this entry. Links to an instance of the User model.
                              If the user is deleted, this field is set to NULL.
    - created_datetime (DateTimeField): The date and time when this entry was created. Automatically set to the current date and time when the entry is created.
    - modified_datetime (DateTimeField): The date and time when this entry was last modified. Automatically updated to the current date and time whenever the entry is saved.
    - last_modified_by (ForeignKey): The user who last modified this entry. Links to an instance of the User model.
                                    If the user is deleted, this field is set to NULL.
    - deleted_datetime (DateTimeField): The date and time when this entry was soft deleted. NULL by default, which means the entry is not deleted.
    - deleted_by (ForeignKey): The user who soft deleted this entry. Links to an instance of the User model.
                              If the user is deleted, this field is set to NULL.
    - upvotes (ManyToManyField): The users who upvoted this entry. Links to instances of the User model.
    - downvotes (ManyToManyField): The users who downvoted this entry. Links to instances of the User model.
    - rating (FloatField): The calculated rating of this entry based on upvotes and downvotes. Default is 0.0.
    - views (PositiveIntegerField): The number of views this entry has received. Default is 0.
    - meta_data (ManyToManyField): The associated tags for this entry. Links to instances of the 'Tag' model.
    """

    title = models.CharField(max_length=255)
    article = models.TextField()
    created_by = models.ForeignKey(
        User, related_name="created_kb_entries", on_delete=models.SET_NULL, null=True
    )
    created_datetime = models.DateTimeField(auto_now_add=True)
    modified_datetime = models.DateTimeField(null=True, blank=True)
    last_modified_by = models.ForeignKey(
        User, related_name="modified_kb_entries", on_delete=models.SET_NULL, null=True
    )
    deleted_datetime = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        User,
        related_name="deleted_kb_entries",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    upvotes = models.ManyToManyField(
        User, related_name="upvoted_kb_entries", blank=True
    )
    downvotes = models.ManyToManyField(
        User, related_name="downvoted_kb_entries", blank=True
    )
    rating = models.FloatField(default=0.0)
    views = models.PositiveIntegerField(default=0)
    meta_data = models.ManyToManyField("Tag", blank=True)


class Tag(models.Model):
    """
    Represents a tag that can be associated with a knowledge base entry.

    Attributes:
    - name (CharField): The name of the tag. Maximum length of 100 characters.

    Methods:
    - __str__(self): Returns a string representation of the Tag model, which is the name of the tag.
    """

    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name  # Assuming 'name' is the field storing the tag's name


class Audit(models.Model):
    """
    Represents an audit log entry to track user actions, including web interactions within the knowledge base system.

    Attributes:
    - user (ForeignKey): Reference to the User model. Represents the user who performed the action. This field can be null if the action was performed by a non-authenticated user or the user context is not available.
    - action_datetime (DateTimeField): Records the date and time when the action was performed. Automatically set to the current date and time when a new log entry is created.
    - kb_entry (ForeignKey): Reference to the KBEntry model. Represents the knowledge base entry related to the action. Can be null if the action did not pertain to a specific knowledge base entry.
    - action_details (CharField): A brief description of the action performed by the user. Maximum length of 255 characters.
    - ip_address (CharField): The IP address from which the action was performed. This field can be left blank and is designed to help in identifying the source of the action for security and auditing purposes.

    The addition of the 'ip_address' attribute enhances the model's capability to log and analyse actions from a security perspective, offering better insight into the source of each action.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    action_datetime = models.DateTimeField(auto_now_add=True)
    kb_entry = models.ForeignKey(KBEntry, on_delete=models.SET_NULL, null=True)
    action_details = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=100, null=True, blank=True)

def calculate_rating(article):
    """
    Calculate the rating of a given article based on upvotes and downvotes.

    Args:
    - article (KBEntry instance): The knowledge base entry (article) for which the rating is to be calculated.

    Returns:
    - list including the rating, number of upvotes, number of downvotes

    This function calculates the percentage of upvotes from the total votes (upvotes and downvotes)
    and returns it as the article's rating. If there are no votes on the article, it returns a rating of 0.0.

    Example:
    If an article has 7 upvotes and 3 downvotes, the rating would be (7 / (7+3)) * 100 = 70.0
    So 70% of voters found the content helpful - 30% voted it down
    This gives us a rating between 0, where no one has yet voted or found it helpful to 100 where everyone who voted - voted it up
    """
    total_votes = article.upvotes.count() + article.downvotes.count()
    upvotes = article.upvotes.count()
    downvotes = article.downvotes.count()

    if total_votes == 0:
        rating_percentage = 0
    else:
        rating_percentage = (upvotes / total_votes) * 100

    return {
        'rating': round(rating_percentage, 1),
        'upvotes': upvotes,
        'downvotes': downvotes,
    }
