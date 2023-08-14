from django.test import TestCase
from knowledge.forms import NewUserForm
from django.contrib.auth.models import User

class NewUserFormTestCase(TestCase):
    
    # Test to make sure user cannot create an account with the same username
    def test_username_taken(self):
        # Create a user to simulate a scenario where the username is already in use.
        User.objects.create(username="testuser")
        form = NewUserForm(data={"username": "testuser"})
        self.assertFalse(form.is_valid())
        self.assertIn("Username is already taken.", form.errors["username"])

    # Test where the user tries to enter all numbers for the username
    def test_username_all_numbers(self):
        form = NewUserForm(data={"username": "123456"})
        self.assertFalse(form.is_valid())
        self.assertIn("Username cannot be all numbers.", form.errors["username"])

    # Test where the username contains a @ symbol
    def test_username_contains_at_symbol(self):
        form = NewUserForm(data={"username": "test@user"})
        self.assertFalse(form.is_valid())
        self.assertIn("Username cannot contain '@'.", form.errors["username"])
        
    # Test where the username contains a space
    def test_username_contains_space(self):
        form = NewUserForm(data={"username": "test user"})
        self.assertFalse(form.is_valid())
        self.assertIn("Username cannot contain spaces.", form.errors["username"])
    
    # Test where the username is longer than 50 characters
    def test_username_too_long(self):
        form = NewUserForm(data={"username": "a" * 51})
        self.assertFalse(form.is_valid())
        self.assertIn("Username cannot be longer than 50 characters.", form.errors["username"])

    # Test where usename is shorter than 3 characters
    def test_username_too_short(self):
        form = NewUserForm(data={"username": "ab"})
        self.assertFalse(form.is_valid())
        self.assertIn("Username must be at least 3 characters long.", form.errors["username"])

    # Test to make sure user cannot create an account with the same email address
    def test_emailaddress_taken(self):
        # Create a user to simulate a scenario where the email address is already in use.
        User.objects.create(username="testuser", email='testuser@testdomain.com')
        form = NewUserForm(data={"username": "testuser2", "email": "testuser@testdomain.com"})
        self.assertFalse(form.is_valid())
        self.assertIn("This email address is already in use.", form.errors["email"])

    # Test a valid registration
    def test_valid_form(self):
        form_data = {
            'username': 'john_doe',
            'email': 'john@example.com',
            'password1': 'SecureP@ss123',
            'password2': 'SecureP@ss123',
        }
        form = NewUserForm(data=form_data)
        self.assertTrue(form.is_valid())

    # Test for use of a common password
    def test_common_password(self):
        form_data = {
            'username': 'john_doe',
            'email': 'john@example.com',
            'password1': 'password',
            'password2': 'password',
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)
    
    # Test for a password that is too short 
    def test_short_password(self):
        form_data = {
            'username': 'john_doe',
            'email': 'john@example.com',
            'password1': 'p4!D',
            'password2': 'p4!D',
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)

    # Test for mismatched password
    def test_mismatched_password(self):
        form_data = {
            'username': 'john_doe',
            'email': 'john@example.com',
            'password1': 'SecureP@ss123',
            'password2': 'DifferentP@ss',
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('password2', form.errors)

    # Test for username already taken in a form
    def test_username_already_taken(self):
        User.objects.create_user(username='existinguser', password='testpass')
        form_data = {
            'username': 'existinguser',
            'email': 'test@example.com',
            'password1': 'SecureP@ss123',
            'password2': 'SecureP@ss123',
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Username is already taken.", form.errors['username'])
    
    # Test for username all numbers in a form 
    def test_username_all_numbers(self):
        form_data = {
            'username': '123456',
            'email': 'test@example.com',
            'password1': 'SecureP@ss123',
            'password2': 'SecureP@ss123',
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Username cannot be all numbers.", form.errors['username'])

    # Test for username already taken in a form
    def test_username_already_taken(self):
        User.objects.create_user(username='existinguser', email='testuser@testdomain.com', password='testpass')
        form_data = {
            'username': 'existinguser',
            'email': 'testuser@testdomain.com',
            'password1': 'SecureP@ss123',
            'password2': 'SecureP@ss123',
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("This email address is already in use.", form.errors['email'])

    # Test for email without an @ sign
    def test_email_without_at(self):
        form_data = {
            'username': 'john_doe',
            'email': 'johnexample.com',  # missing '@'
            'password1': 'SecureP@ss123',
            'password2': 'SecureP@ss123',
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Enter a valid email address.", form.errors['email'])
    
    # Test for email without a dot
    def test_email_without_dot(self):
        form_data = {
            'username': 'john_doe',
            'email': 'john@examplecom',  # missing '.'
            'password1': 'SecureP@ss123',
            'password2': 'SecureP@ss123',
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Enter a valid email address.", form.errors['email'])

    # Test for short email containing @ and .
    def test_short_email(self):
        form_data = {
            'username': 'john_doe',
            'email': 'j@e.a',
            'password1': 'SecureP@ss123',
            'password2': 'SecureP@ss123',
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Enter a valid email address.", form.errors['email'])

#class PasswordResetFormTestCase(TestCase):
    