from strawberry_django_jwt import shortcuts
from strawberry_django_jwt.exceptions import JSONWebTokenError
from tests.testcases import UserTestCase


class ShortcutsTests(UserTestCase):
    def test_get_refresh_token(self):
        refresh_token = shortcuts.create_refresh_token(self.user)
        user = shortcuts.get_refresh_token(refresh_token).user

        self.assertEqual(user, self.user)

    def test_get_refresh_token_error(self):
        with self.assertRaises(JSONWebTokenError):
            shortcuts.get_refresh_token("invalid")
