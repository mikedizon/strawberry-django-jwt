from strawberry_django_jwt import shortcuts
from tests.testcases import UserTestCase


class ShortcutsTests(UserTestCase):
    def test_get_token(self):
        token = shortcuts.get_token(self.user)
        user = shortcuts.get_user_by_token(token)

        self.assertEqual(user, self.user)
