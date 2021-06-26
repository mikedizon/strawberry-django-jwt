from functools import wraps

from django.utils.translation import gettext as _

from .. import exceptions
from ..settings import jwt_settings
from ..utils import get_context


def ensure_refresh_token(f):
    @wraps(f)
    def wrapper(cls, info, refresh_token=None, *args, **kwargs):
        if refresh_token is None:
            cookies = get_context(info).COOKIES
            refresh_token = cookies.get(
                jwt_settings.JWT_REFRESH_TOKEN_COOKIE_NAME,
            )
            if refresh_token is None:
                raise exceptions.JSONWebTokenError(
                    _("Refresh token is required"),
                )
        return f(cls, info, refresh_token, *args, **kwargs)

    return wrapper
