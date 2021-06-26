import inspect
from typing import List
from typing import Optional

import strawberry.django
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission

BORING = dir(type("dummy", (object,), {}))


@strawberry.django.type(Permission)
class PermissionType:
    name: str = ""
    codename: str = ""


@strawberry.django.type(Group)
class GroupType:
    name: str = ""
    permissions: Optional[List[PermissionType]] = None


@strawberry.django.type(AbstractUser)
class UserType:
    def __init__(self, **kwargs):
        for f, v in inspect.getmembers(self, lambda x: not inspect.ismethod(x)):
            if f in BORING:
                continue
            setattr(self, f, kwargs.get(f, v))

    id: Optional[strawberry.ID] = None
    pk: Optional[strawberry.ID] = None
    username: str = ""
    is_authenticated: bool = False
    is_staff: bool = False
    is_active: bool = False
    is_superuser: bool = False
    groups: Optional[List[GroupType]] = None
    user_permissions: Optional[List[PermissionType]] = None
