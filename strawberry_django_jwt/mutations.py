import inspect

import strawberry
from django.contrib.auth import get_user_model
from strawberry.field import StrawberryField

from . import mixins
from .decorators import dispose_extra_kwargs
from .decorators import ensure_token
from .decorators import token_auth
from .object_types import DeleteType
from .object_types import PayloadType
from .object_types import TokenDataType
from .object_types import TokenPayloadType
from .refresh_token.mutations import DeleteRefreshTokenCookie
from .refresh_token.mutations import Revoke

__all__ = [
    "JSONWebTokenMutation",
    "ObtainJSONWebToken",
    "Verify",
    "Refresh",
    "Revoke",
    "DeleteRefreshTokenCookie",
    "DeleteJSONWebTokenCookie",
]

from .settings import jwt_settings

from .utils import get_payload, get_context, create_strawberry_argument


class JSONWebTokenMutation(mixins.JSONWebTokenMixin):
    def __init_subclass__(cls):
        super().__init_subclass__()
        user = get_user_model().USERNAME_FIELD
        field: StrawberryField
        for (name, field) in inspect.getmembers(
            cls, lambda f: isinstance(f, StrawberryField)
        ):
            field.arguments.extend(
                [
                    create_strawberry_argument(user, user, str),
                    create_strawberry_argument("password", "password", str),
                ]
            )


class ObtainJSONWebToken(JSONWebTokenMutation):
    """Obtain JSON Web Token mutation"""

    @strawberry.mutation
    @token_auth
    @dispose_extra_kwargs
    def obtain(self, info) -> TokenDataType:
        return TokenDataType(payload=TokenPayloadType())


class Verify:
    @strawberry.mutation
    @ensure_token
    def verify(self, info, token: str) -> PayloadType:
        return PayloadType(payload=get_payload(token, info.context))


class Refresh(mixins.RefreshMixin):
    pass


class DeleteJSONWebTokenCookie:
    @strawberry.mutation
    def delete_cookie(self, info) -> DeleteType:
        ctx = get_context(info)
        setattr(
            ctx,
            "delete_jwt_cookie",
            jwt_settings.JWT_COOKIE_NAME in ctx.COOKIES
            and getattr(ctx, "jwt_cookie", False),
        )
        return DeleteType(deleted=getattr(ctx, "delete_jwt_cookie"))
