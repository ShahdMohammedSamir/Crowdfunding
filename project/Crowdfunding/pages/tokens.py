from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.crypto import salted_hmac
from django.utils.http import base36_to_int, int_to_base36
import datetime

class AccountActivationTokenGenerator:
    """
    Simple token generator for account activation
    """
    def __init__(self):
        # Use Django's secret key instead of hardcoded one
        from django.conf import settings
        self.secret = settings.SECRET_KEY
        self.timeout = 86400  # 24 hours in seconds

    def make_token(self, user):
        """
        Create a token that can be used once to activate an account
        """
        timestamp = self._num_seconds(datetime.datetime.now())
        return self._make_token_with_timestamp(user, timestamp)

    def check_token(self, user, token):
        """
        Check that the activation token is correct for a given user
        """
        if not (user and token):
            return False
        
        try:
            # Parse token (format: timestamp-hash)
            ts_b36, hash_value = token.split("-")
            timestamp = base36_to_int(ts_b36)
        except (ValueError, TypeError):
            return False
        
        # Check if token is valid
        if not self._constant_time_compare(
            self._make_token_with_timestamp(user, timestamp), 
            token
        ):
            return False
        
        # Check if token has expired (24 hours)
        current_time = self._num_seconds(datetime.datetime.now())
        if (current_time - timestamp) > self.timeout:
            return False
        
        return True

    def _make_token_with_timestamp(self, user, timestamp):
        """
        Generate the actual token string
        """
        ts_b36 = int_to_base36(timestamp)
        hash_string = salted_hmac(
            self.secret,
            self._make_hash_value(user, timestamp),
        ).hexdigest()[::2]  # Shorten to 20 characters
        return f"{ts_b36}-{hash_string}"

    def _make_hash_value(self, user, timestamp):
        """
        Create a hash value that changes when user is activated
        """
        return f"{user.pk}{timestamp}{user.is_active}"

    def _constant_time_compare(self, val1, val2):
        """
        Compare two strings in constant time
        """
        # Use Django's constant_time_compare for security
        from django.utils.crypto import constant_time_compare
        return constant_time_compare(val1, val2)

    def _num_seconds(self, dt):
        """
        Convert datetime to number of seconds since epoch
        """
        return int((dt - datetime.datetime(2001, 1, 1)).total_seconds())

# Create instance
account_activation_token = AccountActivationTokenGenerator()
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

class PasswordResetTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) +
            six.text_type(user.is_active)
        )

password_reset_token = PasswordResetTokenGenerator()