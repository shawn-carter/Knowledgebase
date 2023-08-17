from django.test import TestCase
from knowledge.forms import (
    NewUserForm,
    KBEntryForm,
    RequestPasswordResetForm,
    PasswordResetConfirmForm,
    CustomPasswordChangeForm,
)
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from unittest import mock


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
        self.assertIn(
            "Username cannot be longer than 50 characters.", form.errors["username"]
        )

    # Test where usename is shorter than 3 characters
    def test_username_too_short(self):
        form = NewUserForm(data={"username": "ab"})
        self.assertFalse(form.is_valid())
        self.assertIn(
            "Username must be at least 3 characters long.", form.errors["username"]
        )

    # Test to make sure user cannot create an account with the same email address
    def test_emailaddress_taken(self):
        # Create a user to simulate a scenario where the email address is already in use.
        User.objects.create(username="testuser", email="testuser@testdomain.com")
        form = NewUserForm(
            data={"username": "testuser2", "email": "testuser@testdomain.com"}
        )
        self.assertFalse(form.is_valid())
        self.assertIn("This email address is already in use.", form.errors["email"])

    # Test a valid registration
    def test_valid_form(self):
        form_data = {
            "username": "john_doe",
            "email": "john@example.com",
            "password1": "SecureP@ss123",
            "password2": "SecureP@ss123",
        }
        form = NewUserForm(data=form_data)
        self.assertTrue(form.is_valid())

    # Test for use of a common password
    def test_common_password(self):
        form_data = {
            "username": "john_doe",
            "email": "john@example.com",
            "password1": "password",
            "password2": "password",
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password1", form.errors)

    # Test for a password that is too short
    def test_short_password(self):
        form_data = {
            "username": "john_doe",
            "email": "john@example.com",
            "password1": "p4!D",
            "password2": "p4!D",
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password1", form.errors)

    # Test for mismatched password
    def test_mismatched_password(self):
        form_data = {
            "username": "john_doe",
            "email": "john@example.com",
            "password1": "SecureP@ss123",
            "password2": "DifferentP@ss",
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password2", form.errors)

    # Test for username already taken in a form
    def test_username_already_taken(self):
        User.objects.create_user(username="existinguser", password="testpass")
        form_data = {
            "username": "existinguser",
            "email": "test@example.com",
            "password1": "SecureP@ss123",
            "password2": "SecureP@ss123",
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Username is already taken.", form.errors["username"])

    # Test for username all numbers in a form
    def test_username_all_numbers(self):
        form_data = {
            "username": "123456",
            "email": "test@example.com",
            "password1": "SecureP@ss123",
            "password2": "SecureP@ss123",
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Username cannot be all numbers.", form.errors["username"])

    # Test for username already taken in a form
    def test_username_already_taken(self):
        User.objects.create_user(
            username="existinguser",
            email="testuser@testdomain.com",
            password="testpass",
        )
        form_data = {
            "username": "existinguser",
            "email": "testuser@testdomain.com",
            "password1": "SecureP@ss123",
            "password2": "SecureP@ss123",
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("This email address is already in use.", form.errors["email"])

    # Test for email without an @ sign
    def test_email_without_at(self):
        form_data = {
            "username": "john_doe",
            "email": "johnexample.com",  # missing '@'
            "password1": "SecureP@ss123",
            "password2": "SecureP@ss123",
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Enter a valid email address.", form.errors["email"])

    # Test for email without a dot
    def test_email_without_dot(self):
        form_data = {
            "username": "john_doe",
            "email": "john@examplecom",  # missing '.'
            "password1": "SecureP@ss123",
            "password2": "SecureP@ss123",
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Enter a valid email address.", form.errors["email"])

    # Test for short email containing @ and .
    def test_short_email(self):
        form_data = {
            "username": "john_doe",
            "email": "j@e.a",
            "password1": "SecureP@ss123",
            "password2": "SecureP@ss123",
        }
        form = NewUserForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Enter a valid email address.", form.errors["email"])


class KBEntryFormTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.request = mock.Mock()
        self.request.user = self.user

    def test_valid_form(self):
        form_data = {
            "title": "Sample Article",
            "article": "<p>This is a sample article.</p>",
        }
        form = KBEntryForm(data=form_data, request=self.user)
        self.assertTrue(form.is_valid())

    def test_missing_title(self):
        form_data = {
            "title": "",
            "article": "<p>This is a sample article without title.</p>",
        }
        form = KBEntryForm(data=form_data, request=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn("title", form.errors)

    def test_short_title(self):
        form_data = {
            "title": "Ab",
            "article": "<p>This is a sample article with short title.</p>",
        }
        form = KBEntryForm(data=form_data, request=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn("title", form.errors)

    def test_missing_article(self):
        form_data = {
            "title": "Article without body",
            "article": "",
        }
        form = KBEntryForm(data=form_data, request=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn("article", form.errors)

    def test_short_article(self):
        form_data = {
            "title": "Article with short body",
            "article": "<p>Hi</p>",
        }
        form = KBEntryForm(data=form_data, request=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn("article", form.errors)

    def test_edit_article(self):
        # Create an article
        form_data = {
            "title": "Initial Article",
            "article": "<p>This is the initial version of the article.</p>",
        }
        form = KBEntryForm(data=form_data, request=self.request)
        self.assertTrue(form.is_valid())
        article = form.save()

        # Edit the article
        form_data_edit = {
            "title": "Edited Article",
            "article": "<p>This is the edited version of the article.</p>",
        }
        form_edit = KBEntryForm(
            data=form_data_edit, instance=article, request=self.request
        )
        self.assertTrue(form_edit.is_valid())
        article_edited = form_edit.save()

        self.assertEqual(article_edited.title, "Edited Article")
        self.assertEqual(article_edited.last_modified_by, self.user)


class RequestPasswordResetFormTestCase(TestCase):
    def test_valid_email(self):
        form = RequestPasswordResetForm(data={"email": "john@example.com"})
        self.assertTrue(form.is_valid())

    def test_invalid_email_without_at(self):
        form = RequestPasswordResetForm(data={"email": "johnexample.com"})
        self.assertFalse(form.is_valid())
        self.assertIn("Enter a valid email address.", form.errors["email"])

    def test_invalid_email_without_dot(self):
        form = RequestPasswordResetForm(data={"email": "john@examplecom"})
        self.assertFalse(form.is_valid())
        self.assertIn("Enter a valid email address.", form.errors["email"])


class PasswordResetConfirmFormTestCase(TestCase):
    def test_valid_passwords(self):
        form = PasswordResetConfirmForm(
            data={
                "new_password1": "SecureP@ss123",
                "new_password2": "SecureP@ss123",
            }
        )
        self.assertTrue(form.is_valid())

    def test_passwords_dont_match(self):
        form = PasswordResetConfirmForm(
            data={
                "new_password1": "SecureP@ss123",
                "new_password2": "DifferentP@ss",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn(
            "The two password fields didn’t match.", form.errors["new_password2"]
        )

    def test_short_passwords(self):
        form = PasswordResetConfirmForm(
            data={
                "new_password1": "A4!i0s",
                "new_password2": "A4!i0s",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn(
            "This password is too short. It must contain at least 8 characters.",
            form.errors["new_password1"],
        )

    def test_common_password(self):
        form = PasswordResetConfirmForm(
            data={
                "new_password1": "password123",
                "new_password2": "password123",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("This password is too common.", form.errors["new_password1"])


class CustomPasswordChangeFormTestCase(TestCase):
    def test_valid_password_change(self):
        user = User.objects.create_user(username="john", password="old_password")
        form = CustomPasswordChangeForm(
            user,
            data={
                "old_password": "old_password",
                "new_password1": "new_secure_password1",
                "new_password2": "new_secure_password1",
            },
        )
        self.assertTrue(form.is_valid())

    def test_incorrect_old_password(self):
        user = User.objects.create_user(username="john", password="old_password")
        form = CustomPasswordChangeForm(
            user,
            data={
                "old_password": "wrong_old_password",
                "new_password1": "new_secure_password1",
                "new_password2": "new_secure_password1",
            },
        )
        self.assertFalse(form.is_valid())
        self.assertIn("old_password", form.errors)

    def test_new_passwords_dont_match(self):
        user = User.objects.create_user(username="john", password="old_password")
        form = CustomPasswordChangeForm(
            user,
            data={
                "old_password": "old_password",
                "new_password1": "new_secure_password1",
                "new_password2": "different_new_password",
            },
        )
        self.assertFalse(form.is_valid())
        self.assertIn("new_password2", form.errors)

    def test_short_new_password(self):
        user = User.objects.create_user(username="john", password="old_password")
        form = CustomPasswordChangeForm(
            user,
            data={
                "old_password": "old_password",
                "new_password1": "short",
                "new_password2": "short",
            },
        )
        self.assertFalse(form.is_valid())
        self.assertIn("new_password1", form.errors)

    def test_common_new_password(self):
        user = User.objects.create_user(username="john", password="old_password")
        form = CustomPasswordChangeForm(
            user,
            data={
                "old_password": "old_password",
                "new_password1": "password123",
                "new_password2": "password123",
            },
        )
        self.assertFalse(form.is_valid())
        self.assertIn("new_password1", form.errors)
