"""authentik admin Middleware to impersonate users"""
import json
from contextvars import ContextVar
from typing import Callable, Optional
from uuid import uuid4

from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.utils.translation import activate
from sentry_sdk.api import set_tag
from structlog.contextvars import STRUCTLOG_KEY_PREFIX

SESSION_KEY_IMPERSONATE_USER = "authentik/impersonate/user"
SESSION_KEY_IMPERSONATE_ORIGINAL_USER = "authentik/impersonate/original_user"
RESPONSE_HEADER_ID = "X-authentik-id"
KEY_AUTH_VIA = "auth_via"
KEY_USER = "user"

CTX_REQUEST_ID = ContextVar[Optional[str]](STRUCTLOG_KEY_PREFIX + "request_id", default=None)
CTX_HOST = ContextVar[Optional[str]](STRUCTLOG_KEY_PREFIX + "host", default=None)
CTX_AUTH_VIA = ContextVar[Optional[str]](STRUCTLOG_KEY_PREFIX + KEY_AUTH_VIA, default=None)


class ImpersonateMiddleware:
    """Middleware to impersonate users"""

    get_response: Callable[[HttpRequest], HttpResponse]

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # No permission checks are done here, they need to be checked before
        # SESSION_KEY_IMPERSONATE_USER is set.
        if request.user.is_authenticated:
            locale = request.user.locale(request)
            if locale != "":
                activate(locale)

        if SESSION_KEY_IMPERSONATE_USER in request.session:
            request.user = request.session[SESSION_KEY_IMPERSONATE_USER]
            # Ensure that the user is active, otherwise nothing will work
            request.user.is_active = True

        return self.get_response(request)


class RequestIDMiddleware:
    """Add a unique ID to every request"""

    get_response: Callable[[HttpRequest], HttpResponse]

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if not hasattr(request, "request_id"):
            request_id = uuid4().hex
            setattr(request, "request_id", request_id)
            CTX_REQUEST_ID.set(request_id)
            CTX_HOST.set(request.get_host())
            set_tag("authentik.request_id", request_id)
        if hasattr(request, "user") and getattr(request.user, "is_authenticated", False):
            CTX_AUTH_VIA.set("session")
        else:
            CTX_AUTH_VIA.set("unauthenticated")

        response = self.get_response(request)

        response[RESPONSE_HEADER_ID] = request.request_id
        setattr(response, "ak_context", {})
        response.ak_context["request_id"] = CTX_REQUEST_ID.get()
        response.ak_context["host"] = CTX_HOST.get()
        response.ak_context[KEY_AUTH_VIA] = CTX_AUTH_VIA.get()
        response.ak_context[KEY_USER] = request.user.username
        return response


class APILimitMiddleware:
    """接口请求限制"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        api_path = request.path
        response = self.get_response(request)

        if api_path not in ("/api/v3/core/users/login/", "/api/v3/core/users/register/"):
            return response

        ip_address = request.META.get("REMOTE_ADDR")
        cache_key = f"api_request_limit:{ip_address}:{api_path}"
        request_count = cache.get(cache_key, 0)
        if request_count >= 60:
            response_data = json.dumps({"data": "", "msg": "请勿频繁操作", "code": 500})
            return HttpResponse(response_data, content_type="application/json")

        cache.set(cache_key, request_count + 1, 60)
        return response
