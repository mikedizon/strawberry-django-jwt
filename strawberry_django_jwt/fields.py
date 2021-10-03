from typing import List, Optional

from strawberry.arguments import StrawberryArgument
from strawberry_django.arguments import argument


class StrawberryDjangoTokenField:
    @property
    def arguments(self) -> List[StrawberryArgument]:
        return super().arguments + [argument("token", Optional[str])]


class StrawberryDjangoRefreshTokenField:
    @property
    def arguments(self) -> List[StrawberryArgument]:
        return super().arguments + [argument("refresh_token", Optional[str])]
