# knowledge/forms.py
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.forms import PasswordChangeForm
from .models import KBEntry

class NewUserForm(forms.ModelForm):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput)
    email = forms.EmailField(required=True)  # Ensure email is required

    class Meta:
        model = User
        fields = ('username', 'email')

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError("Username is already taken.")
        if username.isdigit():
            raise ValidationError("Username cannot be all numbers.")
        if '@' in username:
            raise ValidationError("Username cannot contain '@'.")
        if ' ' in username:
            raise ValidationError("Username cannot contain spaces.")
        if username == 'admin':
            raise ValidationError("Username cannot be 'admin'.")
        if len(username) > 50:
            raise ValidationError("Username cannot be longer than 50 characters.")
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters long.")
        return username
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        # Check if email already exists
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email address is already in use.")
        return email

    def clean_password1(self):
        password1 = self.cleaned_data.get('password1')
        validate_password(password1)  # This will raise a ValidationError if the password is not valid
        return password1

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        # Check if password1 is valid
        if password1:
            # Check if password1 matches password2
            if password1 != password2:
                self.add_error('password2', "Passwords must match")
        return cleaned_data
    
    def save(self, commit=True):
        user = super(NewUserForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

class PasswordResetForm(forms.Form):
    username = forms.CharField(max_length=50)
    new_password1 = forms.CharField(widget=forms.PasswordInput, label='Password')
    new_password2 = forms.CharField(widget=forms.PasswordInput, label='Confirm Password')

    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get('new_password1')
        validate_password(new_password1)  # This will raise a ValidationError if the password is not valid
        return new_password1

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')

        if not User.objects.filter(username=username).exists():
            self.add_error('username', 'No user with this username exists.')

        if new_password1 and new_password2 and new_password1 != new_password2:
            self.add_error('new_password2', 'The two password fields didn’t match.')

class CustomPasswordChangeForm(PasswordChangeForm):

    def clean_new_password1(self):
        password1 = self.cleaned_data.get('new_password1')
        
        # Run the default password validations
        validate_password(password1)
        
        return password1

class RequestPasswordResetForm(forms.Form):
    email = forms.EmailField()

class PasswordResetConfirmForm(forms.Form):
    new_password1 = forms.CharField(widget=forms.PasswordInput, label='New Password')
    new_password2 = forms.CharField(widget=forms.PasswordInput, label='Confirm New Password')

class KBEntryForm(forms.ModelForm):
    class Meta:
        model = KBEntry
        fields = ['title', 'article']  # Excluding 'meta_data' here
        widgets = {
            'article': forms.Textarea(attrs={'required': False}),
        }

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super(KBEntryForm, self).__init__(*args, **kwargs)

    def save(self, commit=True):
        instance = super(KBEntryForm, self).save(commit=False)
        if not instance.pk:  # Check if the instance has a primary key (i.e., if it's been saved before)
            instance.created_by = self.request.user
        instance.last_modified_by = self.request.user
        if commit:
            instance.save()
            self.save_m2m()
        return instance