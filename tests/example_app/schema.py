from typing import List

import strawberry
from strawberry import Schema

from strawberry_django_jwt.decorators import login_required
from strawberry_django_jwt.middleware import JSONWebTokenMiddleware


@strawberry.type
class Query:
    @strawberry.field
    @login_required
    def week_days(self) -> List[str]:
        return [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ]


schema = Schema(query=Query, extensions=[JSONWebTokenMiddleware])
