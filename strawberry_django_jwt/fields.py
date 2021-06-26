from typing import Any, Union, Awaitable, Dict

from strawberry.field import StrawberryField


class ExtendedStrawberryField(StrawberryField):
    def get_result(
        self, source: Any, info: Any, kwargs: Dict[str, Any]
    ) -> Union[Awaitable[Any], Any]:
        if self.base_resolver:
            args, kwargs = self._get_arguments(source, info=info, kwargs=kwargs)
            kwargs["info"] = info
            return self.base_resolver(*args, **kwargs)
        return getattr(source, self.python_name)
