from typing import List, Optional

from strawberry.arguments import StrawberryArgument
from strawberry.field import StrawberryField
from strawberry_django.arguments import argument


class StrawberryDjangoTokenField(StrawberryField):
    @property
    def arguments(self) -> List[StrawberryArgument]:
        return super().arguments + [argument("token", Optional[str])]


class StrawberryDjangoRefreshTokenField(StrawberryField):
    @property
    def arguments(self) -> List[StrawberryArgument]:
        return super().arguments + [argument("refresh_token", Optional[str])]
