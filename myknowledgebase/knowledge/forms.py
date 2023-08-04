# knowledge/forms.py
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

class NewUserForm(forms.ModelForm):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput)
    email = forms.EmailField(required=True)  # Ensure email is required

    class Meta:
        model = User
        fields = ('username', 'email')

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if len(username) < 4:
            raise ValidationError("Username must be at least 4 characters long.")
        return username

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")
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
    username = forms.CharField(max_length=150)
    new_password1 = forms.CharField(widget=forms.PasswordInput, label='Password')
    new_password2 = forms.CharField(widget=forms.PasswordInput, label='Confirm Password')
    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')

        if not User.objects.filter(username=username).exists():
            self.add_error('username', 'No user with this username exists.')

        if new_password1 and new_password2 and new_password1 != new_password2:
            self.add_error('new_password2', 'The two password fields didn’t match.')
