import django
import strawberry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from strawberry.types import Info

from strawberry_django_jwt.decorators import dispose_extra_kwargs
from strawberry_django_jwt.decorators import login_required
from strawberry_django_jwt.mixins import OptionalJSONWebTokenMixin
from strawberry_django_jwt.mixins import RequestInfoMixin
from strawberry_django_jwt.model_object_types import UserType
from strawberry_django_jwt.settings import jwt_settings
from strawberry_django_jwt.shortcuts import get_token
from .decorators import OverrideJwtSettings
from .testcases import SchemaTestCase


class QueriesTests(SchemaTestCase):
    @strawberry.type
    class Query(RequestInfoMixin, OptionalJSONWebTokenMixin):
        @strawberry.field
        @dispose_extra_kwargs
        def test(self, info) -> UserType:
            ret = UserType(**info.context.user.__dict__)
            return ret

    def setUp(self):
        super().setUp()

        self.other_user = get_user_model().objects.create_user("other")
        self.other_token = get_token(self.other_user)

    def test_login_required(self):
        @strawberry.type
        class Query(RequestInfoMixin, OptionalJSONWebTokenMixin):
            @strawberry.field
            @login_required
            def test(self) -> str:
                return "TEST"

            @strawberry.field
            @login_required
            def test_info(self, info: Info) -> str:
                return "TEST-INFO"

        self.client.schema(query=Query, mutation=self.Mutation)

        query = """
        query Test {
            test
            testInfo
        }
        """

        headers = {
            jwt_settings.JWT_AUTH_HEADER_NAME: f"{jwt_settings.JWT_AUTH_HEADER_PREFIX} {self.token}",
        }

        response = self.client.execute(query, **headers)
        data = response.data

        self.assertEqual(data["test"], "TEST")
        self.assertIsNone(response.errors)

    @OverrideJwtSettings(JWT_ALLOW_ARGUMENT=True)
    def test_multiple_credentials(self):
        query = """
        query Tests($token: String!, $otherToken: String!) {{
          testBegin: test {{
            username
          }}
          testToken: test({0}: $token) {{
            username
          }}
          testOtherToken: test({0}: $otherToken) {{
            username
          }}
          testEnd: test {{
            username
          }}
        }}""".format(
            jwt_settings.JWT_ARGUMENT_NAME
        )

        headers = {
            jwt_settings.JWT_AUTH_HEADER_NAME: f"{jwt_settings.JWT_AUTH_HEADER_PREFIX} {self.token}",
        }

        variables = {
            "token": self.token,
            "otherToken": self.other_token,
        }

        response = self.client.execute(query, variables, **headers)
        data = response.data

        self.assertEqual(data["testBegin"].get("username"), self.user.username)
        self.assertEqual(data["testEnd"].get("username"), self.user.username)
        self.assertEqual(data["testToken"].get("username"), self.user.username)
        self.assertEqual(
            data["testOtherToken"].get("username"), self.other_user.username
        )

        self.assertIsNone(response.errors)

    @OverrideJwtSettings(JWT_ALLOW_ARGUMENT=True)
    def test_invalid_credentials(self):
        query = """
        query Tests {{
          testInvalidToken: test({0}: "invalid") {{
            username
          }}
        }}""".format(
            jwt_settings.JWT_ARGUMENT_NAME
        )

        self.client.authenticate(self.token)

        response = self.client.execute(query)
        data = response.data

        self.assertIsNone(data)
        self.assertEqual(len(response.errors), 1)

    @OverrideJwtSettings(
        JWT_ALLOW_ARGUMENT=True,
        JWT_ALLOW_ANY_CLASSES=[
            "graphql.type.definition.GraphQLType",
        ],
    )
    def test_allow_any(self):
        query = f"""
        {{
          testAllowAny: test {{
            username
            id
          }}
          testInvalidToken: test({jwt_settings.JWT_ARGUMENT_NAME}: "invalid") {{
            username
            id
          }}
        }}"""

        self.client.authenticate("invalid")

        response = self.client.execute(query)

        self.assertIsNone(response.data["testAllowAny"].get("id"), AnonymousUser)
        self.assertEqual(response.data["testAllowAny"].get("username"), "")
        self.assertIsNone(response.data["testInvalidToken"].get("id"), AnonymousUser)
        self.assertEqual(response.data["testInvalidToken"].get("username"), "")


if django.VERSION[:2] >= (3, 1):
    from .testcases import AsyncSchemaTestCase

    class AsyncQueriesTests(AsyncSchemaTestCase):
        @strawberry.type
        class Query(RequestInfoMixin, OptionalJSONWebTokenMixin):
            @strawberry.field
            @dispose_extra_kwargs
            async def test(self, info) -> UserType:
                ret = UserType(**info.context.user.__dict__)
                return ret

        def setUp(self):
            super().setUp()

            self.other_user = get_user_model().objects.create_user("other")
            self.other_token = get_token(self.other_user)

        async def test_login_required(self):
            @strawberry.type
            class Query(RequestInfoMixin, OptionalJSONWebTokenMixin):
                @strawberry.field
                @login_required
                async def test(self) -> str:
                    return "TEST"

                @strawberry.field
                @login_required
                async def test_info(self, info: Info) -> str:
                    return "TEST-INFO"

            self.client.schema(query=Query, mutation=self.Mutation)

            query = """
            query Test {
                test
                testInfo
            }
            """

            self.client.authenticate(self.token)

            response = await self.client.execute(query)
            data = response.data

            self.assertEqual(data["test"], "TEST")
            self.assertIsNone(response.errors)

        @OverrideJwtSettings(JWT_ALLOW_ARGUMENT=True)
        async def test_multiple_credentials(self):
            query = """
            query Tests($token: String!, $otherToken: String!) {{
              testBegin: test {{
                username
              }}
              testToken: test({0}: $token) {{
                username
              }}
              testOtherToken: test({0}: $otherToken) {{
                username
              }}
              testEnd: test {{
                username
              }}
            }}""".format(
                jwt_settings.JWT_ARGUMENT_NAME
            )

            self.client.authenticate(self.token)

            variables = {
                "token": self.token,
                "otherToken": self.other_token,
            }

            response = await self.client.execute(query, variables)
            data = response.data

            self.assertEqual(data["testBegin"].get("username"), self.user.username)
            self.assertEqual(data["testEnd"].get("username"), self.user.username)
            self.assertEqual(data["testToken"].get("username"), self.user.username)
            self.assertEqual(
                data["testOtherToken"].get("username"), self.other_user.username
            )

            self.assertIsNone(response.errors)

        @OverrideJwtSettings(JWT_ALLOW_ARGUMENT=True)
        async def test_invalid_credentials(self):
            query = """
            query Tests {{
              testInvalidToken: test({0}: "invalid") {{
                username
              }}
            }}""".format(
                jwt_settings.JWT_ARGUMENT_NAME
            )

            self.client.authenticate(self.token)

            response = await self.client.execute(query)
            data = response.data

            self.assertIsNone(data)
            self.assertEqual(len(response.errors), 1)

        @OverrideJwtSettings(
            JWT_ALLOW_ARGUMENT=True,
            JWT_ALLOW_ANY_CLASSES=[
                "graphql.type.definition.GraphQLType",
            ],
        )
        async def test_allow_any(self):
            query = f"""
            {{
              testAllowAny: test {{
                username
                id
              }}
              testInvalidToken: test({jwt_settings.JWT_ARGUMENT_NAME}: "invalid") {{
                username
                id
              }}
            }}"""

            self.client.authenticate("invalid")

            response = await self.client.execute(query)

            self.assertIsNone(response.data["testAllowAny"].get("id"), AnonymousUser)
            self.assertEqual(response.data["testAllowAny"].get("username"), "")
            self.assertIsNone(
                response.data["testInvalidToken"].get("id"), AnonymousUser
            )
            self.assertEqual(response.data["testInvalidToken"].get("username"), "")
