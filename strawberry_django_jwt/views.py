from typing import cast
from typing import Optional

import django
from django.http import HttpRequest
from django.http import HttpResponse
from django.http import JsonResponse
from strawberry.django.views import BaseView
from strawberry.django.views import GraphQLView
from strawberry.http import GraphQLHTTPResponse
from strawberry.http import process_result
from strawberry.types import ExecutionResult
from strawberry_django_jwt.exceptions import JSONWebTokenError


class StatusGraphQLHTTPResponse(GraphQLHTTPResponse):
    status: Optional[int]


def make_status_response(response: GraphQLHTTPResponse) -> StatusGraphQLHTTPResponse:
    res = cast(StatusGraphQLHTTPResponse, response)
    res["status"] = 200
    return res


class BaseStatusHandlingGraphQLView(BaseView):
    def _create_response(
        self, response_data: GraphQLHTTPResponse, sub_response: HttpResponse
    ) -> JsonResponse:
        data = cast(StatusGraphQLHTTPResponse, response_data)
        response = JsonResponse(data, status=data.get("status", None))

        for name, value in sub_response.items():
            response[name] = value

        return response


class StatusHandlingGraphQLView(BaseStatusHandlingGraphQLView, GraphQLView):
    def process_result(
        self, request: HttpRequest, result: ExecutionResult
    ) -> StatusGraphQLHTTPResponse:
        res = make_status_response(process_result(result))
        if result.errors:
            if any(
                isinstance(err, JSONWebTokenError)
                for err in [e.original_error for e in result.errors]
            ):
                res["status"] = 401
        return res


if django.VERSION[:2] >= (3, 1):
    from strawberry.django.views import AsyncGraphQLView

    class AsyncStatusHandlingGraphQLView(
        BaseStatusHandlingGraphQLView, AsyncGraphQLView
    ):
        async def process_result(
            self, request: HttpRequest, result: ExecutionResult
        ) -> StatusGraphQLHTTPResponse:
            res = make_status_response(process_result(result))
            if result.errors:
                if any(
                    isinstance(err, JSONWebTokenError)
                    for err in [e.original_error for e in result.errors]
                ):
                    res["status"] = 401
            return res
