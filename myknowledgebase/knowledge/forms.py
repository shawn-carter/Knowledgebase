# knowledge/forms.py
from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.utils.html import strip_tags
from .models import KBEntry


class NewUserForm(forms.ModelForm):
    """
    A form for creating new users. Includes all the required fields,
    plus a repeated password field for validation.
    """
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirm Password", widget=forms.PasswordInput)
    email = forms.EmailField(required=True)  # Ensure email is required

    # Define new init to ensure that fields are returned if one field is invalid
    def __init__(self, *args, **kwargs):
        # Get the raw POST data from the kwargs
        post_data = kwargs.get('data', None)
        
        # If there's POST data, update the kwargs with a copy of the POST data
        if post_data:
            kwargs['data'] = post_data.copy()
        
        # Call the parent class's __init__ method
        super().__init__(*args, **kwargs)

    class Meta:      
        model = User
        fields = ("username", "email")

    # Check the username to make sure it is not already in use
    # Additional validation to make sure the username does not contain only numbers, and cannot contain @ or spaces
    # Checks to ensure the username is within defined length and is not 'admin'
    def clean_username(self):
        username = self.cleaned_data.get("username")
        if User.objects.filter(username=username).exists():
            raise ValidationError("Username is already taken.")
        if username.isdigit():
            raise ValidationError("Username cannot be all numbers.")
        if "@" in username:
            raise ValidationError("Username cannot contain '@'.")
        if " " in username:
            raise ValidationError("Username cannot contain spaces.")
        if username == "admin":
            raise ValidationError("Username cannot be 'admin'.")
        if len(username) > 50:
            raise ValidationError("Username cannot be longer than 50 characters.")
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters long.")
        return username

    # Check that email address is unique and not already in use
    def clean_email(self):
        email = self.cleaned_data.get("email")
        # Check if email already exists
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email address is already in use.")
        return email

    # Check if the password is valid using Django built in validate_password function
    # This checks for common and simple password
    def clean_password1(self):
        password1 = self.cleaned_data.get("password1")
        validate_password(
            password1
        )  # This will raise a ValidationError if the password is not valid
        return password1

    # Check that passwords match
    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        # Check if password1 is valid
        if password1:
            # Check if password1 matches password2
            if password1 != password2:
                self.add_error("password2", "Passwords must match")
        return cleaned_data

    # Save the user with new password = password1
    def save(self, commit=True):
        user = super(NewUserForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user
    

class CustomPasswordChangeForm(PasswordChangeForm):
    """
    A form that allows a user to change their existing password (logged in authenticated user)
    Includes existing password field
    plus a repeated password field for validation.
    """
    def clean_new_password1(self):
        password1 = self.cleaned_data.get("new_password1")

        # Run the default password validations
        validate_password(password1)

        return password1


class RequestPasswordResetForm(forms.Form):
    """
    A simple form for requesting a password reset.
    This just contains an email address
    This is validated with Django built in functions
    """

    email = forms.EmailField()


class KBEntryForm(forms.ModelForm):
    """
    A form for creating a new article. Includes all the required fields,
    This form is also used to allow a user to edit an existing article.
    """

    article = forms.CharField(widget=forms.Textarea, required=False, initial="")

    class Meta:
        model = KBEntry
        fields = ["title", "article"]  # Excluding 'meta_data' here

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request", None)
        super(KBEntryForm, self).__init__(*args, **kwargs)

    # Ensure the title contains at least 3 characters
    def clean_title(self):
        title = self.cleaned_data.get("title")
        if len(title) < 3:
            raise ValidationError("Article Title should be at least 3 characters.")
        return title

    # Ensure the article contains at least 10 characters (after stripping tags)
    def clean_article(self):
        title = self.cleaned_data.get("title")
        article = self.cleaned_data.get("article")
        # Strip HTML tags and white spaces for validation
        plain_text = strip_tags(article).strip()
        if len(plain_text) < 10:
            raise ValidationError("Article Body should contain at least 10 characters.")
        # Always return the original article data, not the stripped version
        return article

    def save(self, commit=True):
        instance = super(KBEntryForm, self).save(commit=False)
        if (
            not instance.pk
        ):  # Check if the instance has a primary key (i.e., if it's been saved before)
            instance.created_by = self.request.user
        instance.last_modified_by = self.request.user
        if commit:
            instance.save()
            self.save_m2m()
        return instance


class PasswordResetConfirmForm(forms.Form):
    """
    A form for reseting a users password (not authenticated user)
    Consists of a repeated password field for validation.
    """

    new_password1 = forms.CharField(widget=forms.PasswordInput, label="New Password")
    new_password2 = forms.CharField(
        widget=forms.PasswordInput, label="Confirm New Password"
    )

    # This validates the first password field using Django built in validate_password function
    # Which will give an error if the password is common or too simple
    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get("new_password1")
        validate_password(
            new_password1
        )  # This will raise a ValidationError if the password is not valid
        return new_password1

    ## We then clean and compare the two password fields to ensure they match
    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get("new_password1")
        new_password2 = cleaned_data.get("new_password2")

        if new_password1 and new_password2 and new_password1 != new_password2:
            self.add_error("new_password2", "The two password fields didn’t match.")

        return cleaned_data
