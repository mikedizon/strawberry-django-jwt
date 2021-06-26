from django.test import override_settings


class OverrideJwtSettings(override_settings):
    def __init__(self, **kwargs):
        super().__init__(strawberry_django_jwt=kwargs)
