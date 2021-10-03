import strawberry_django
from strawberry_django import auto

from tests import models


@strawberry_django.type(models.MyTestModel)
class MyTestModel:
    test: auto
