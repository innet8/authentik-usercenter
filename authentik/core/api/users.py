"""User API Views"""
import base64
import datetime
import hashlib
import random
import re
import uuid
from datetime import timedelta
from io import BytesIO
from json import loads
from typing import Any, Optional

import jwt
from django.conf import settings
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sessions.backends.cache import KEY_PREFIX
from django.core import mail
from django.core.cache import cache
from django.db.models.functions import ExtractHour
from django.db.transaction import atomic
from django.db.utils import IntegrityError
from django.http import HttpResponse
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.http import urlencode
from django.utils.text import slugify
from django.utils.timezone import now
from django.utils.translation import gettext as _
from django_filters.filters import (
    BooleanFilter,
    CharFilter,
    ModelMultipleChoiceFilter,
    MultipleChoiceFilter,
    UUIDFilter,
)
from django_filters.filterset import FilterSet
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_field,
    inline_serializer,
)
from guardian.shortcuts import get_anonymous_user, get_objects_for_user
from PIL import Image, ImageDraw, ImageFilter, ImageFont
from rest_framework.decorators import action
from rest_framework.fields import (
    CharField,
    IntegerField,
    JSONField,
    ListField,
    SerializerMethodField,
)
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import (
    BooleanField,
    DateTimeField,
    ListSerializer,
    ModelSerializer,
    PrimaryKeyRelatedField,
    ValidationError,
)
from rest_framework.validators import UniqueValidator
from rest_framework.viewsets import ModelViewSet
from structlog.stdlib import get_logger

from authentik.admin.api.metrics import CoordinateSerializer
from authentik.api.decorators import permission_required
from authentik.blueprints.v1.importer import SERIALIZER_CONTEXT_BLUEPRINT
from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import LinkSerializer, PassiveSerializer, is_dict
from authentik.core.middleware import (
    SESSION_KEY_IMPERSONATE_ORIGINAL_USER,
    SESSION_KEY_IMPERSONATE_USER,
)
from authentik.core.models import (
    USER_ATTRIBUTE_TOKEN_EXPIRING,
    USER_PATH_SERVICE_ACCOUNT,
    AuthenticatedSession,
    Group,
    Token,
    TokenIntents,
    User,
    UserTypes,
)
from authentik.events.models import Event, EventAction
from authentik.flows.exceptions import FlowNonApplicableException
from authentik.flows.models import FlowToken
from authentik.flows.planner import PLAN_CONTEXT_PENDING_USER, FlowPlanner
from authentik.flows.views.executor import QS_KEY_TOKEN
from authentik.lib.config import CONFIG
from authentik.stages.email.models import EmailStage
from authentik.stages.email.tasks import send_mails
from authentik.stages.email.utils import TemplateEmailMessage
from authentik.tenants.models import Tenant
from django.core.paginator import Paginator


LOGGER = get_logger()


class UserGroupSerializer(ModelSerializer):
    """Simplified Group Serializer for user's groups"""

    attributes = JSONField(required=False)
    parent_name = CharField(source="parent.name", read_only=True)

    class Meta:
        model = Group
        fields = [
            "pk",
            "num_pk",
            "name",
            "is_superuser",
            "parent",
            "parent_name",
            "attributes",
        ]


class UserSerializer(ModelSerializer):
    """User Serializer"""

    is_superuser = BooleanField(read_only=True)
    avatar = CharField(read_only=True)
    attributes = JSONField(validators=[is_dict], required=False)
    groups = PrimaryKeyRelatedField(
        allow_empty=True, many=True, source="ak_groups", queryset=Group.objects.all(), default=list
    )
    groups_obj = ListSerializer(child=UserGroupSerializer(), read_only=True, source="ak_groups")
    uid = CharField(read_only=True)
    username = CharField(max_length=150, validators=[UniqueValidator(queryset=User.objects.all())])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if SERIALIZER_CONTEXT_BLUEPRINT in self.context:
            self.fields["password"] = CharField(required=False, allow_null=True)

    def create(self, validated_data: dict) -> User:
        """If this serializer is used in the blueprint context, we allow for
        directly setting a password. However should be done via the `set_password`
        method instead of directly setting it like rest_framework."""
        password = validated_data.pop("password", None)
        instance: User = super().create(validated_data)
        self._set_password(instance, password)
        return instance

    def update(self, instance: User, validated_data: dict) -> User:
        """Same as `create` above, set the password directly if we're in a blueprint
        context"""
        password = validated_data.pop("password", None)
        instance = super().update(instance, validated_data)
        self._set_password(instance, password)
        return instance

    def _set_password(self, instance: User, password: Optional[str]):
        """Set password of user if we're in a blueprint context, and if it's an empty
        string then use an unusable password"""
        if SERIALIZER_CONTEXT_BLUEPRINT in self.context and password:
            instance.set_password(password)
            instance.save()
        if len(instance.password) == 0:
            instance.set_unusable_password()
            instance.save()

    def validate_path(self, path: str) -> str:
        """Validate path"""
        if path[:1] == "/" or path[-1] == "/":
            raise ValidationError(_("No leading or trailing slashes allowed."))
        for segment in path.split("/"):
            if segment == "":
                raise ValidationError(_("No empty segments in user path allowed."))
        return path

    def validate_type(self, user_type: str) -> str:
        """Validate user type, internal_service_account is an internal value"""
        if (
            self.instance
            and self.instance.type == UserTypes.INTERNAL_SERVICE_ACCOUNT
            and user_type != UserTypes.INTERNAL_SERVICE_ACCOUNT.value
        ):
            raise ValidationError("Can't change internal service account to other user type.")
        if not self.instance and user_type == UserTypes.INTERNAL_SERVICE_ACCOUNT.value:
            raise ValidationError("Setting a user to internal service account is not allowed.")
        return user_type

    class Meta:
        model = User
        fields = [
            "pk",
            "username",
            "name",
            "is_active",
            "last_login",
            "is_superuser",
            "groups",
            "groups_obj",
            "email",
            "avatar",
            "attributes",
            "uid",
            "path",
            "type",
            "uuid",
        ]
        extra_kwargs = {
            "name": {"allow_blank": True},
        }


class UserSelfSerializer(ModelSerializer):
    """User Serializer for information a user can retrieve about themselves"""

    is_superuser = BooleanField(read_only=True)
    avatar = CharField(read_only=True)
    groups = SerializerMethodField()
    uid = CharField(read_only=True)
    settings = SerializerMethodField()
    system_permissions = SerializerMethodField()

    @extend_schema_field(
        ListSerializer(
            child=inline_serializer(
                "UserSelfGroups",
                {"name": CharField(read_only=True), "pk": CharField(read_only=True)},
            )
        )
    )
    def get_groups(self, _: User):
        """Return only the group names a user is member of"""
        for group in self.instance.all_groups().order_by("name"):
            yield {
                "name": group.name,
                "pk": group.pk,
            }

    def get_settings(self, user: User) -> dict[str, Any]:
        """Get user settings with tenant and group settings applied"""
        return user.group_attributes(self._context["request"]).get("settings", {})

    def get_system_permissions(self, user: User) -> list[str]:
        """Get all system permissions assigned to the user"""
        return list(
            user.user_permissions.filter(
                content_type__app_label="authentik_rbac", content_type__model="systempermission"
            ).values_list("codename", flat=True)
        )

    class Meta:
        model = User
        fields = [
            "pk",
            "username",
            "name",
            "is_active",
            "is_superuser",
            "groups",
            "email",
            "avatar",
            "uid",
            "settings",
            "type",
            "system_permissions",
        ]
        extra_kwargs = {
            "is_active": {"read_only": True},
            "name": {"allow_blank": True},
        }


class SessionUserSerializer(PassiveSerializer):
    """Response for the /user/me endpoint, returns the currently active user (as `user` property)
    and, if this user is being impersonated, the original user in the `original` property."""

    user = UserSelfSerializer()
    original = UserSelfSerializer(required=False)


class UserMetricsSerializer(PassiveSerializer):
    """User Metrics"""

    logins = SerializerMethodField()
    logins_failed = SerializerMethodField()
    authorizations = SerializerMethodField()

    @extend_schema_field(CoordinateSerializer(many=True))
    def get_logins(self, _):
        """Get successful logins per 8 hours for the last 7 days"""
        user = self.context["user"]
        request = self.context["request"]
        return (
            get_objects_for_user(request.user, "authentik_events.view_event").filter(
                action=EventAction.LOGIN, user__pk=user.pk
            )
            # 3 data points per day, so 8 hour spans
            .get_events_per(timedelta(days=7), ExtractHour, 7 * 3)
        )

    @extend_schema_field(CoordinateSerializer(many=True))
    def get_logins_failed(self, _):
        """Get failed logins per 8 hours for the last 7 days"""
        user = self.context["user"]
        request = self.context["request"]
        return (
            get_objects_for_user(request.user, "authentik_events.view_event").filter(
                action=EventAction.LOGIN_FAILED, context__username=user.username
            )
            # 3 data points per day, so 8 hour spans
            .get_events_per(timedelta(days=7), ExtractHour, 7 * 3)
        )

    @extend_schema_field(CoordinateSerializer(many=True))
    def get_authorizations(self, _):
        """Get failed logins per 8 hours for the last 7 days"""
        user = self.context["user"]
        request = self.context["request"]
        return (
            get_objects_for_user(request.user, "authentik_events.view_event").filter(
                action=EventAction.AUTHORIZE_APPLICATION, user__pk=user.pk
            )
            # 3 data points per day, so 8 hour spans
            .get_events_per(timedelta(days=7), ExtractHour, 7 * 3)
        )


class UsersFilter(FilterSet):
    """Filter for users"""

    attributes = CharFilter(
        field_name="attributes",
        lookup_expr="",
        label="Attributes",
        method="filter_attributes",
    )

    is_superuser = BooleanFilter(field_name="ak_groups", lookup_expr="is_superuser")
    uuid = UUIDFilter(field_name="uuid")

    path = CharFilter(field_name="path")
    path_startswith = CharFilter(field_name="path", lookup_expr="startswith")

    type = MultipleChoiceFilter(choices=UserTypes.choices, field_name="type")

    groups_by_name = ModelMultipleChoiceFilter(
        field_name="ak_groups__name",
        to_field_name="name",
        queryset=Group.objects.all(),
    )
    groups_by_pk = ModelMultipleChoiceFilter(
        field_name="ak_groups",
        queryset=Group.objects.all(),
    )

    def filter_attributes(self, queryset, name, value):
        """Filter attributes by query args"""
        try:
            value = loads(value)
        except ValueError:
            raise ValidationError(detail="filter: failed to parse JSON")
        if not isinstance(value, dict):
            raise ValidationError(detail="filter: value must be key:value mapping")
        qs = {}
        for key, _value in value.items():
            qs[f"attributes__{key}"] = _value
        try:
            _ = len(queryset.filter(**qs))
            return queryset.filter(**qs)
        except ValueError:
            return queryset

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "name",
            "is_active",
            "is_superuser",
            "attributes",
            "groups_by_name",
            "groups_by_pk",
            "type",
        ]


class UserViewSet(UsedByMixin, ModelViewSet):
    """User Viewset"""

    queryset = User.objects.none()
    ordering = ["username"]
    serializer_class = UserSerializer
    search_fields = ["username", "name", "is_active", "email", "uuid"]
    filterset_class = UsersFilter

    def get_queryset(self):  # pragma: no cover
        return User.objects.all().exclude(pk=get_anonymous_user().pk)

    def _create_recovery_link(self) -> tuple[Optional[str], Optional[Token]]:
        """Create a recovery link (when the current tenant has a recovery flow set),
        that can either be shown to an admin or sent to the user directly"""
        tenant: Tenant = self.request._request.tenant
        # Check that there is a recovery flow, if not return an error
        flow = tenant.flow_recovery
        if not flow:
            LOGGER.debug("No recovery flow set")
            return None, None
        user: User = self.get_object()
        planner = FlowPlanner(flow)
        planner.allow_empty_flows = True
        try:
            plan = planner.plan(
                self.request._request,
                {
                    PLAN_CONTEXT_PENDING_USER: user,
                },
            )
        except FlowNonApplicableException:
            LOGGER.warning("Recovery flow not applicable to user")
            return None, None
        token, __ = FlowToken.objects.update_or_create(
            identifier=f"{user.uid}-password-reset",
            defaults={
                "user": user,
                "flow": flow,
                "_plan": FlowToken.pickle(plan),
            },
        )
        querystring = urlencode({QS_KEY_TOKEN: token.key})
        link = self.request.build_absolute_uri(
            reverse_lazy("authentik_core:if-flow", kwargs={"flow_slug": flow.slug})
            + f"?{querystring}"
        )
        return link, token

    @permission_required(None, ["authentik_core.add_user", "authentik_core.add_token"])
    @extend_schema(
        request=inline_serializer(
            "UserServiceAccountSerializer",
            {
                "name": CharField(required=True),
                "create_group": BooleanField(default=False),
                "expiring": BooleanField(default=True),
                "expires": DateTimeField(
                    required=False,
                    help_text="If not provided, valid for 360 days",
                ),
            },
        ),
        responses={
            200: inline_serializer(
                "UserServiceAccountResponse",
                {
                    "username": CharField(required=True),
                    "token": CharField(required=True),
                    "user_uid": CharField(required=True),
                    "user_pk": IntegerField(required=True),
                    "group_pk": CharField(required=False),
                },
            )
        },
    )
    @action(detail=False, methods=["POST"], pagination_class=None, filter_backends=[])
    def service_account(self, request: Request) -> Response:
        """Create a new user account that is marked as a service account"""
        username = request.data.get("name")
        create_group = request.data.get("create_group", False)
        expiring = request.data.get("expiring", True)
        expires = request.data.get("expires", now() + timedelta(days=360))

        with atomic():
            try:
                user: User = User.objects.create(
                    username=username,
                    name=username,
                    type=UserTypes.SERVICE_ACCOUNT,
                    attributes={USER_ATTRIBUTE_TOKEN_EXPIRING: expiring},
                    path=USER_PATH_SERVICE_ACCOUNT,
                )
                user.set_unusable_password()
                user.save()

                response = {
                    "username": user.username,
                    "user_uid": user.uid,
                    "user_pk": user.pk,
                }
                if create_group and self.request.user.has_perm("authentik_core.add_group"):
                    group = Group.objects.create(
                        name=username,
                    )
                    group.users.add(user)
                    response["group_pk"] = str(group.pk)
                token = Token.objects.create(
                    identifier=slugify(f"service-account-{username}-password"),
                    intent=TokenIntents.INTENT_APP_PASSWORD,
                    user=user,
                    expires=expires,
                    expiring=expiring,
                )
                response["token"] = token.key
                return Response(response)
            except IntegrityError as exc:
                return Response(data={"non_field_errors": [str(exc)]}, status=400)

    @extend_schema(responses={200: SessionUserSerializer(many=False)})
    @action(url_path="me", url_name="me", detail=False, pagination_class=None, filter_backends=[])
    def user_me(self, request: Request) -> Response:
        """Get information about current user"""
        context = {"request": request}
        serializer = SessionUserSerializer(
            data={"user": UserSelfSerializer(instance=request.user, context=context).data}
        )
        if SESSION_KEY_IMPERSONATE_USER in request._request.session:
            serializer.initial_data["original"] = UserSelfSerializer(
                instance=request._request.session[SESSION_KEY_IMPERSONATE_ORIGINAL_USER],
                context=context,
            ).data
        self.request.session.modified = True
        return Response(serializer.initial_data)

    @permission_required("authentik_core.reset_user_password")
    @extend_schema(
        request=inline_serializer(
            "UserPasswordSetSerializer",
            {
                "password": CharField(required=True),
            },
        ),
        responses={
            204: OpenApiResponse(description="Successfully changed password"),
            400: OpenApiResponse(description="Bad request"),
        },
    )
    @action(detail=True, methods=["POST"])
    def set_password(self, request: Request, pk: int) -> Response:
        """Set password for user"""
        user: User = self.get_object()
        try:
            password = request.data.get("password")
            if not password:
                return Response({"password": ["密码不能为空"]}, status=400)
            pattern2 = r"^(?:(?=.*[A-Z])(?=.*[a-z])|(?=.*[A-Z])(?=.*[0-9])|(?=.*[A-Z])(?=.*[^A-Za-z0-9])|(?=.*[a-z])(?=.*[0-9])|(?=.*[a-z])(?=.*[^A-Za-z0-9])|(?=.*[0-9])(?=.*[^A-Za-z0-9])).{6,24}$"
            if not re.match(pattern2, password):
                return Response({"password": ["密码: 6~24位，支持大小写字母、数字、英文特殊字符，需包含2种类型以上"]}, status=400)
            user.set_password(request.data.get("password"))
            user.save()
        except (ValidationError, IntegrityError) as exc:
            LOGGER.debug("Failed to set password", exc=exc)
            return Response(status=400)
        if user.pk == request.user.pk and SESSION_KEY_IMPERSONATE_USER not in self.request.session:
            LOGGER.debug("Updating session hash after password change")
            update_session_auth_hash(self.request, user)
        return Response(status=204)

    @permission_required("authentik_core.view_user", ["authentik_events.view_event"])
    @extend_schema(responses={200: UserMetricsSerializer(many=False)})
    @action(detail=True, pagination_class=None, filter_backends=[])
    def metrics(self, request: Request, pk: int) -> Response:
        """User metrics per 1h"""
        user: User = self.get_object()
        serializer = UserMetricsSerializer(instance={})
        serializer.context["user"] = user
        serializer.context["request"] = request
        return Response(serializer.data)

    @permission_required("authentik_core.reset_user_password")
    @extend_schema(
        responses={
            "200": LinkSerializer(many=False),
            "404": LinkSerializer(many=False),
        },
    )
    @action(detail=True, pagination_class=None, filter_backends=[])
    def recovery(self, request: Request, pk: int) -> Response:
        """Create a temporary link that a user can use to recover their accounts"""
        link, _ = self._create_recovery_link()
        if not link:
            LOGGER.debug("Couldn't create token")
            return Response({"link": ""}, status=404)
        return Response({"link": link})

    @permission_required("authentik_core.reset_user_password")
    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="email_stage",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.STR,
                required=True,
            )
        ],
        responses={
            "204": OpenApiResponse(description="Successfully sent recover email"),
            "404": OpenApiResponse(description="Bad request"),
        },
    )
    @action(detail=True, pagination_class=None, filter_backends=[])
    def recovery_email(self, request: Request, pk: int) -> Response:
        """Create a temporary link that a user can use to recover their accounts"""
        for_user: User = self.get_object()
        if for_user.email == "":
            LOGGER.debug("User doesn't have an email address")
            return Response(status=404)
        link, token = self._create_recovery_link()
        if not link:
            LOGGER.debug("Couldn't create token")
            return Response(status=404)
        # Lookup the email stage to assure the current user can access it
        stages = get_objects_for_user(
            request.user, "authentik_stages_email.view_emailstage"
        ).filter(pk=request.query_params.get("email_stage"))
        if not stages.exists():
            LOGGER.debug("Email stage does not exist/user has no permissions")
            return Response(status=404)
        email_stage: EmailStage = stages.first()
        message = TemplateEmailMessage(
            subject=_(email_stage.subject),
            to=[for_user.email],
            template_name=email_stage.template,
            language=for_user.locale(request),
            template_context={
                "url": link,
                "user": for_user,
                "expires": token.expires,
            },
        )
        send_mails(email_stage, message)
        return Response(status=204)

    @permission_required("authentik_core.impersonate")
    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={
            "204": OpenApiResponse(description="Successfully started impersonation"),
            "401": OpenApiResponse(description="Access denied"),
        },
    )
    @action(detail=True, methods=["POST"])
    def impersonate(self, request: Request, pk: int) -> Response:
        """Impersonate a user"""
        if not CONFIG.get_bool("impersonation"):
            LOGGER.debug("User attempted to impersonate", user=request.user)
            return Response(status=401)
        if not request.user.has_perm("impersonate"):
            LOGGER.debug("User attempted to impersonate without permissions", user=request.user)
            return Response(status=401)
        user_to_be = self.get_object()
        if user_to_be.pk == self.request.user.pk:
            LOGGER.debug("User attempted to impersonate themselves", user=request.user)
            return Response(status=401)

        request.session[SESSION_KEY_IMPERSONATE_ORIGINAL_USER] = request.user
        request.session[SESSION_KEY_IMPERSONATE_USER] = user_to_be

        Event.new(EventAction.IMPERSONATION_STARTED).from_http(request, user_to_be)

        return Response(status=201)

    @extend_schema(
        request=OpenApiTypes.NONE,
        responses={
            "204": OpenApiResponse(description="Successfully started impersonation"),
        },
    )
    @action(detail=False, methods=["GET"])
    def impersonate_end(self, request: Request) -> Response:
        """End Impersonation a user"""
        if (
            SESSION_KEY_IMPERSONATE_USER not in request.session
            or SESSION_KEY_IMPERSONATE_ORIGINAL_USER not in request.session
        ):
            LOGGER.debug("Can't end impersonation", user=request.user)
            return Response(status=204)

        original_user = request.session[SESSION_KEY_IMPERSONATE_ORIGINAL_USER]

        del request.session[SESSION_KEY_IMPERSONATE_USER]
        del request.session[SESSION_KEY_IMPERSONATE_ORIGINAL_USER]

        Event.new(EventAction.IMPERSONATION_ENDED).from_http(request, original_user)

        return Response(status=204)

    @extend_schema(
        responses={
            200: inline_serializer(
                "UserPathSerializer", {"paths": ListField(child=CharField(), read_only=True)}
            )
        },
        parameters=[
            OpenApiParameter(
                name="search",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.STR,
            )
        ],
    )
    @action(detail=False, pagination_class=None)
    def paths(self, request: Request) -> Response:
        """Get all user paths"""
        return Response(
            data={
                "paths": list(
                    self.filter_queryset(self.get_queryset())
                    .values("path")
                    .distinct()
                    .order_by("path")
                    .values_list("path", flat=True)
                )
            }
        )

    def partial_update(self, request: Request, *args, **kwargs) -> Response:
        response = super().partial_update(request, *args, **kwargs)
        instance: User = self.get_object()
        if not instance.is_active:
            sessions = AuthenticatedSession.objects.filter(user=instance)
            session_ids = sessions.values_list("session_key", flat=True)
            cache.delete_many(f"{KEY_PREFIX}{session}" for session in session_ids)
            sessions.delete()
            LOGGER.debug("Deleted user's sessions", user=instance.username)
        return response

    @extend_schema(
        request=inline_serializer(
            "UserServiceAccountSerializer",
            {
                "username": CharField(required=True),
                "password": CharField(required=True),
            },
        ),
        responses={
            200: inline_serializer(
                "UserServiceAccountResponse",
                {
                    "username": CharField(required=True),
                    "user_uid": CharField(required=True),
                    "user_pk": IntegerField(required=True),
                    "group_pk": CharField(required=False),
                },
            )
        },
    )
    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def register(self, request: Request) -> Response:
        """用户注册"""

        if "username" not in request.data:
            return self.errUserResponse("", "账号不能为空")
        if cache.get("EmailLock::" + request.data.get("username")):
            return self.errUserResponse("", "请勿频繁操作，120s后再重新提交请求")
        if len(request.data.get("username")) > 100:
            return self.errUserResponse("", "账号必须为邮箱格式且最长100个字符")
        pattern1 = r"^[A-Za-z0-9\u4e00-\u9fa5]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){1,100}$"
        if not re.match(pattern1, request.data.get("username")):
            return self.errUserResponse("", "账号必须为邮箱格式且最长100个字符")
        if "password" not in request.data:
            return self.errUserResponse("", "密码不能为空")

        pattern2 = r"^(?:(?=.*[A-Z])(?=.*[a-z])|(?=.*[A-Z])(?=.*[0-9])|(?=.*[A-Z])(?=.*[^A-Za-z0-9])|(?=.*[a-z])(?=.*[0-9])|(?=.*[a-z])(?=.*[^A-Za-z0-9])|(?=.*[0-9])(?=.*[^A-Za-z0-9])).{6,24}$"
        if not re.match(pattern2, request.data.get("password")):
            return self.errUserResponse("", "密码: 6~24位，支持大小写字母、数字、英文特殊字符，需包含2种类型以上")
        if "source" not in request.data:
            return self.errUserResponse("", "来源不能为空")

        username = request.data.get("username")
        source = request.data.get("source")
        source_url = request.data.get("source_url", "")

        if User.objects.filter(
            username=request.data.get("username"), is_verify_email=True
        ).exists():
            return self.errUserResponse("", "账号已存在")

        with atomic():
            try:
                oldUser = User.objects.filter(
                    username=request.data.get("username"), is_verify_email=False
                ).first()
                if oldUser:
                    oldUser.delete()
                user: User = User.objects.create(
                    username=username,
                    email=username,
                    name=username,
                    type=UserTypes.EXTERNAL,
                    path=source,
                    is_verify_email=False,
                )
                user.set_password(request.data.get("password"))
                user.save()
                # 生成6位数字验证码
                email_code = "".join(str(random.randint(0, 9)) for _ in range(6))
                hash_object = hashlib.md5(email_code.encode())
                md5_hash = hash_object.hexdigest()
                cache.set(md5_hash, username, 600)

                lang = request.META.get('HTTP_LANGUAGE');
                subject = "Mailbox verification"
                if lang == 'zh-cn' or lang == 'zh' :
                    subject = "邮箱验证"
                if lang == 'zh-tw' or lang == 'tc' or lang == 'zh-CHT':
                    subject = "郵箱驗證"

                verification_link = (
                    CONFIG.get("app_url")
                    + "page/activate?code="
                    + md5_hash
                    + "&source_url="
                    + source_url
                    + "&language="
                    + lang
                )  # 消息内容

                result = mail.send_mail(
                    subject=subject,  # 题目
                    message="注册验证",
                    from_email=settings.DEFAULT_FROM_EMAIL,  # 发送者
                    recipient_list=[username],  # 接收者邮件列表
                    html_message=render_to_string(
                        "email/verify_email.html",
                        {"username": username, "verification_link": verification_link, "language": lang},
                    ),
                )
                if result == 1:
                    cache.set("EmailLock::" + username, 1, 120)
                    return self.sucUserResponse("", "邮件发送成功")
                else:
                    return self.errUserResponse("", "邮件发送失败")
            except IntegrityError as exc:
                return self.errUserResponse("", str(exc))
            except Exception as e:
                return self.errUserResponse("", f"邮件发送出现异常: {str(e)}")

    @extend_schema(
        request=inline_serializer(
            "UserServiceAccountSerializer",
            {
                "username": CharField(required=True),
                "password": CharField(required=True),
            },
        ),
        responses={
            200: inline_serializer(
                "UserServiceAccountResponse",
                {
                    "username": CharField(required=True),
                    "user_uid": CharField(required=True),
                    "user_pk": IntegerField(required=True),
                    "group_pk": CharField(required=False),
                },
            )
        },
    )
    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def login(self, request: Request) -> Response:
        """用户登录"""
        if "username" not in request.data:
            return self.errUserResponse("", "账号不能为空")
        if "password" not in request.data:
            return self.errUserResponse("", "密码不能为空")
        attempts_key = f'password_attempts_{request.data.get("username")}'
        attempts = cache.get(attempts_key, 0)
        if attempts >= 4:
            if "pic_code" not in request.data:
                return self.errUserResponse("", "请输入图形验证码")
            verify_key = f'verify_pic_code_{request.data.get("username")}'
            verify_pic_code = cache.get(verify_key, "")
            if verify_pic_code.lower() != request.data.get("pic_code").lower():
                return self.errUserResponse("", "图形验证码错误")

        try:
            user = User.objects.get(username=request.data.get("username"))
            if not user:
                return self.errUserResponse("", "账号不存在")
            if not user.is_active:
                return self.errUserResponse("", "账号已禁用")
            if user.type != UserTypes.EXTERNAL:
                return self.errUserResponse("", "禁止登录")
            if user.password == '':
                return self.errUserResponse("", "请前往安全升级", 10)
            if not user.is_verify_email:
                return self.errUserResponse("", "邮箱未验证")
            re = user.check_password(request.data.get("password"))
            if re:
                # 设置 JWT 的 payload 数据
                payload = {
                    "username": user.username,
                    "source": user.path,
                    "exp": datetime.datetime.utcnow() + settings.JWT_EXPIRATION_DELTA,  # 设置过期时间为当前时间的一天后
                }
                token = jwt.encode(
                    payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
                )
                data = {"token": base64.b64encode(token.encode())}
                # 登录成功，重置密码错误次数
                cache.delete(attempts_key)
                return self.sucUserResponse(data)
            else:
                # 登录失败，增加密码错误次数
                attempts = cache.get(attempts_key, 0)
                attempt_num = attempts + 1
                cache.set(attempts_key, attempt_num, 600)  # 设置过期时间为10分钟
                if attempt_num >= 4:
                    return self.errUserResponse("needcode", "账号或密码错误")
                return self.errUserResponse("", "账号或密码错误")
        except User.DoesNotExist:
            return self.errUserResponse("", "账号不存在")
        except IntegrityError as exc:
            return self.errUserResponse("", str(exc))

    @extend_schema(
        request=inline_serializer(
            "UserServiceAccountSerializer",
            {
                "token": CharField(required=True),
            },
        ),
        responses={
            200: inline_serializer(
                "UserServiceAccountResponse",
                {
                    "username": CharField(required=True),
                    "user_uid": CharField(required=True),
                    "user_pk": IntegerField(required=True),
                },
            )
        },
    )
    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def update_password(self, request: Request) -> Response:
        """更新密码"""
        if not self.check_api_token(request):
            return self.errUserResponse("", "INVALID TOKENk")
        username = request.data.get("username")
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return self.errUserResponse("", "账号不存在")

        if not user.check_password(old_password):
            return self.errUserResponse("", "原密码错误")

        is_valid_password, msg = self.validate_password(new_password)
        if not is_valid_password:
            return self.errUserResponse("", msg)
        if not confirm_password:
            return self.errUserResponse("", "确认密码不能为空")
        if new_password != confirm_password:
            return self.errUserResponse("", "新密码和确认密码不匹配")

        user.set_password(new_password)
        user.save()
        return self.sucUserResponse("", "更新密码成功")

    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def update_email(self, request: Request) -> Response:
        """更新邮箱"""
        if not self.check_api_token(request):
            return self.errUserResponse("", "INVALID TOKENk")

        step = request.data.get("step", 1)
        sign = request.data.get("sign")
        username = request.data.get("username")
        new_email = request.data.get("new_email")
        email_code = request.data.get("code")
        language = request.META.get('HTTP_LANGUAGE')

        # 发送验证码
        if step == 1:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return self.errUserResponse("", "账号不存在")

            is_sent, message = self.dispatch_email(user.username, "original_email", language, "")
            if is_sent:
                return self.sucUserResponse({
                    "step": step,
                    "sign": self.generate_sign(user.username, str(step))
                })
            else:
                return self.errUserResponse("", message)

        # 验证验证码
        if step == 2:
            is_valid_sign, message_or_username = self.verify_sign(sign, str(step-1))
            if not is_valid_sign:
                return self.errUserResponse("", message_or_username)

            is_valid_code, msg = self.verify_dispatch_email_code(message_or_username, str(email_code))
            if not is_valid_code:
                return self.errUserResponse("", msg)

            return self.sucUserResponse({
                "step": step,
                "sign": self.generate_sign(message_or_username, str(step))
            }, "验证成功")

        # 发送新邮箱的验证码
        if step == 3:
            is_valid_sign, message_or_username = self.verify_sign(sign, str(step-1))
            if not is_valid_sign:
                return self.errUserResponse("", message_or_username)

            if User.objects.filter(username=new_email).exists():
                return self.errUserResponse("", "邮箱已存在")

            is_sent, message = self.dispatch_email(new_email, "new_email", language, "")
            if is_sent:
                return self.sucUserResponse({
                    "step": step,
                    "sign": self.generate_sign(message_or_username, str(step))
                }, message)
            else:
                return self.errUserResponse("", message)

        #更改
        if step == 4:
            is_valid_sign, message_or_username = self.verify_sign(sign, str(step-1))
            if not is_valid_sign:
                return self.errUserResponse("", message_or_username)

            is_valid_code, msg = self.verify_dispatch_email_code(new_email, str(email_code))
            if not is_valid_code:
                return self.errUserResponse("", msg)

            try:
                user = User.objects.get(username=message_or_username)
            except User.DoesNotExist:
                return self.errUserResponse("", "账号不存在")

            user.username = user.email = user.name = new_email
            user.save()
            return self.sucUserResponse({ "step": step }, "更新邮箱成功")

        else:
            return self.errUserResponse("", "无效操作")

    def generate_sign(self, username: str, step: str) -> tuple[str]:
        """验证签名"""
        sign = hashlib.md5( (step + str(uuid.uuid4())).encode() ).hexdigest()
        cache.set("sign_email::" + sign + step, username, 30 * 60)
        return sign

    def verify_sign(self, sign: str, step: str) -> tuple[bool, str]:
        """验证签名"""
        username = cache.get("sign_email::" + sign + step)
        if not sign:
            return False, "无效签名"
        if not username:
            return False, "无效请求"
        return True, username

    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def force_reset_password(self, request: Request) -> Response:
        """重置密码"""
        if not self.check_api_token(request):
            return self.errUserResponse("", "INVALID TOKENk")

        if "password" not in request.data:
            return self.errUserResponse("", "参数错误")

        username = request.data.get("username")
        password = request.data.get("password")
        pattern2 = r"^(?:(?=.*[A-Z])(?=.*[a-z])|(?=.*[A-Z])(?=.*[0-9])|(?=.*[A-Z])(?=.*[^A-Za-z0-9])|(?=.*[a-z])(?=.*[0-9])|(?=.*[a-z])(?=.*[^A-Za-z0-9])|(?=.*[0-9])(?=.*[^A-Za-z0-9])).{6,24}$"
        if not re.match(pattern2, password):
            return self.errUserResponse("", "密码: 6~24位，支持大小写字母、数字、英文特殊字符，需包含2种类型以上")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return self.errUserResponse("", "账号不存在")
        user.set_password(password)
        user.save()
        return self.sucUserResponse("", "密码已成功重置")

    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def reset_password(self, request: Request) -> Response:
        """重置密码"""
        step = request.data.get("step")
        source_url = request.data.get("source_url", "")
        if step == 1:
            username = request.data.get("username")
            is_sent, message = self.dispatch_email(
                username, "retrieve_password", request.META.get('HTTP_LANGUAGE'), source_url
            )
            if is_sent:
                return self.sucUserResponse("", message)
            else:
                return self.errUserResponse("", message)
        else:
            link_code = request.data.get("link_code")
            new_password = request.data.get("new_password")

            username = cache.get(link_code)
            if not username:
                return self.errUserResponse("", "链接已失效，请重新提交请求")
            is_valid_password, msg = self.validate_password(new_password)
            if not is_valid_password:
                return self.errUserResponse("", msg)

            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return self.errUserResponse("", "账号不存在")

            user.set_password(new_password)
            user.save()
            cache.delete(link_code)
            return self.sucUserResponse("", "密码已成功重置")

    def validate_username(self, username: str) -> tuple[bool, str]:
        """验证用户名"""
        if not username:
            return False, "账号不能为空"
        if len(username) > 100:
            return False, "账号必须为邮箱格式且最长100个字符"
        pattern = r"^[A-Za-z0-9\u4e00-\u9fa5]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){1,100}$"
        if not re.match(pattern, username):
            return False, "账号必须为邮箱格式且最长100个字符"
        return True, ""

    def validate_password(self, password: str) -> tuple[bool, str]:
        """验证密码"""
        if not password:
            return False, "新密码不能为空"
        pattern = r"^(?:(?=.*[A-Z])(?=.*[a-z])|(?=.*[A-Z])(?=.*[0-9])|(?=.*[A-Z])(?=.*[^A-Za-z0-9])|(?=.*[a-z])(?=.*[0-9])|(?=.*[a-z])(?=.*[^A-Za-z0-9])|(?=.*[0-9])(?=.*[^A-Za-z0-9])).{6,24}$"
        if not re.match(pattern, password):
            return False, "密码: 6~24位，支持大小写字母、数字、英文特殊字符，需包含2种类型以上"
        return True, ""

    def dispatch_email( self, username: str, key: str, lang: str, source_url: str) -> tuple[bool, str]:
        """邮件发送：找回密码(retrieve_password)、更改邮箱(original_email)、启用邮箱(new_email)"""
        is_valid_username, msg = self.validate_username(username)
        if not is_valid_username:
            return False, msg

        if cache.get("EmailLock::" + username):
            return False, "请勿频繁操作，120s后再重新提交请求"

        user = None
        if key == "retrieve_password":
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return False, "账号不存在"

        subject = "Reset your password"
        subject_two = "Update your email"
        subject_three = "Activate your email"
        if lang == 'zh-cn' or lang == 'zh' :
            subject = "重置您的密码"
            subject_two = "更改您的邮箱"
            subject_three = "启用您的邮箱"
        if lang == 'zh-tw' or lang == 'tc' or lang == 'zh-CHT':
            subject = "重設您的密碼"
            subject_two = "更改您的郵箱"
            subject_three = "啟用您的郵箱"

        email_config = {
            "retrieve_password": {
                "subject": subject,
                "template": "email/retrieve_password.html",
                "success_text": "邮件下发成功，请前往邮箱进行重置密码",
                "token": str(default_token_generator.make_token(user)) if user else "",
            },
            "original_email": {
                "subject": subject_two,
                "template": "email/original_email.html",
                "success_text": "邮件发送成功",
                "token": "".join(str(random.randint(0, 9)) for _ in range(6)),
            },
            "new_email": {
                "subject": subject_three,
                "template": "email/new_email.html",
                "success_text": "邮件发送成功",
                "token": "".join(str(random.randint(0, 9)) for _ in range(6)),
            },
        }

        if key not in email_config:
            return False, "无效的邮件类型"

        config = email_config[key]
        token = config["token"]
        hash_object = hashlib.md5(token.encode())
        md5_hash = hash_object.hexdigest()
        cache.set(md5_hash, username, 30 * 60)
        link = (
            CONFIG.get("app_url")
            + "api/v3/core/users/verify_retrieve_password/?code="
            + md5_hash
            + "&source_url="
            + source_url
            + "&lang="
            + lang
        )

        html_message = render_to_string(
            config["template"],
            {
                "link": link,
                "verification_code": token,
                "language": lang,
            },
        )
        result = mail.send_mail(
            subject=config["subject"],
            message=config["subject"],
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[username],
            html_message=html_message,
        )
        if result == 1:
            cache.set("EmailLock::" + username, 1, 120)
            return True, config["success_text"]
        else:
            return False, "邮件发送失败"

    def check_api_token(self, request: Request) -> bool:
        """检查API令牌是否有效"""

        if "HTTP_APITOKEN" in request.META:
            apitoken = request.META["HTTP_APITOKEN"]
            if any(token_dict["api_token"] == apitoken for token_dict in CONFIG.get("business")):
                return True
        return False

    def check_token(self, token: str) -> tuple[bool, str or User]:
        """检测令牌"""
        if not token:
            return False, "令牌不能为空"
        try:
            token = base64.b64decode(token).decode()
            decoded_payload = jwt.decode(
                token, settings.JWT_SECRET_KEY, algorithms=settings.JWT_ALGORITHM
            )
            username = decoded_payload.get("username")
            user = User.objects.get(username=username)
            return True, user
        except UnicodeDecodeError:
            return False, "无效令牌"
        except jwt.ExpiredSignatureError:
            return False, "令牌已过期"
        except jwt.InvalidTokenError:
            return False, "无效令牌"
        except User.DoesNotExist:
            return False, "账号不存在"
        except Exception:
            return False, "无效令牌"

    def verify_dispatch_email_code(self, username: str, code: str) -> tuple[bool, str]:
        """验证验证码"""
        if not code:
            return False, "验证码不能为空"
        hash_object = hashlib.md5(code.encode())
        md5_hash = hash_object.hexdigest()
        val = cache.get(md5_hash)
        if not val:
            return False, "验证码已失效，请重新获取"
        if username == val:
            cache.set(md5_hash, "", 600)
            return True, "验证成功"
        else:
            return False, "验证码错误"

    @action(detail=False, methods=["GET"], permission_classes=[AllowAny])
    def verify_retrieve_password(self, request: Request) -> Response:
        """验证忘记密码链接"""
        code = request.query_params.get("code")
        lang = request.query_params.get("lang")
        source_url = request.query_params.get("source_url") + "?lang=" + lang
        if not code:
            return self.errUserResponse("", "code不能为空")
        username = cache.get(code)
        if not username:
            # "链接已失效，请重新提交请求"
            if lang == 'zh-cn' or lang == 'zh' :
                return Response('链接已失效，请重新提交请求', status=200)
            if lang == 'zh-tw' or lang == 'tc' or lang == 'zh-CHT':
                return Response('链接已失效，请重新提交请求', status=200)
            return Response('The link is no longer available, please resubmit the request', status=200)

        user = User.objects.filter(username=username).first()
        if user:
            return redirect(
                CONFIG.get("app_url")
                + "page/resetPassword?link_code="
                + code
                + "&source_url="
                + source_url
                + "&language="
                + lang
            )
        else:
            return self.errUserResponse("", "用户不存在")

    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def get_info(self, request: Request) -> Response:
        """Decode token to getUser"""
        if "token" not in request.data:
            return self.errUserResponse("", "令牌不能为空")

        try:
            token = base64.b64decode(request.data.get("token")).decode()
            decoded_payload = jwt.decode(
                token, settings.JWT_SECRET_KEY, algorithms=settings.JWT_ALGORITHM
            )
        except UnicodeDecodeError:
            return self.errUserResponse("", "无效令牌")
        except jwt.ExpiredSignatureError:
            return self.errUserResponse("", "令牌已过期")
        except jwt.InvalidTokenError:
            return self.errUserResponse("", "无效令牌")
        except Exception:
            return self.errUserResponse("", "无效令牌")

        return self.sucUserResponse(decoded_payload)

    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def get_user_info(self, request: Request) -> Response:
        """Decode token to getUser"""
        if not self.check_api_token(request):
            return self.errUserResponse("", "INVALID TOKENk")

        if "email" not in request.data:
            return self.errUserResponse("", "参数错误")

        user = User.objects.filter(email=request.data.get("email"), type="external").first()
        if user:
            data = {
                "id": user.id,
                "last_login": user.last_login,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "is_active": user.is_active,
                "date_joined": user.date_joined,
                "uuid": user.uuid,
                "name": user.name,
                "password_change_date": user.password_change_date,
                "attributes": user.attributes,
                "path": user.path,
                "is_verify_email": user.is_verify_email
            }
            return self.sucUserResponse(data)
        else:
            return self.errUserResponse("", "用户不存在")

    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def get_list(self, request: Request) -> Response:
        """获取用户列表"""
        if not self.check_api_token(request):
            return self.errUserResponse("", "INVALID TOKENk")

        Userdb = User.objects.filter(type="external")

        if "emails" in request.data:
            if len(request.data.get("emails")) > 1000:
                return self.errUserResponse("", "emails参数不能大于1000")
            if len(request.data.get("emails")) > 0:
                Userdb = Userdb.filter(email__in=request.data.get("emails"))

        users = Userdb.values(
                "id",
                "username",
                "last_login",
                "first_name",
                "last_name",
                "email",
                "is_active",
                "date_joined",
                "uuid",
                "name",
                "password_change_date",
                "attributes",
                "path",
                "is_verify_email",
            )
        page_number = request.data.get("page",1)
        page_size = request.data.get("page_size",100)
        user_data = list( Paginator(users, per_page=page_size).get_page(int(page_number)) )
        return self.sucUserResponse(user_data)


    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def updateEmailVerify(self, request: Request) -> Response:
        """更改用户邮箱验证状态"""
        if not self.check_api_token(request):
            return self.errUserResponse("", "INVALID TOKENk")

        if "username" not in request.data:
            return self.errUserResponse("", "账号不能为空")
        if "is_verify_email" not in request.data:
            return self.errUserResponse("", "验证状态不能为空")

        user = User.objects.filter(
            username=request.data.get("username"), type="external"
        ).first()
        if user:
            user.is_verify_email = True if request.data.get("is_verify_email") == 1 else False
            user.save()
            return self.sucUserResponse("", "修改成功")
        else:
            return self.errUserResponse("", "用户不存在")

    @action(detail=False, methods=["GET"], permission_classes=[AllowAny])
    def verifyRegisterEmail(self, request: Request) -> Response:
        """验证注册邮箱"""
        code = request.query_params.get("code")
        if not code:
            return self.errUserResponse("", "code不能为空")
        username = cache.get(code)
        if not username:
            return self.errUserResponse("", "链接已失效，请重新注册")
        user = User.objects.filter(username=username).first()
        if user:
            user.is_verify_email = True
            user.save()
            return self.sucUserResponse("", "邮箱验证成功")
        else:
            return self.errUserResponse("", "用户不存在")

    @action(detail=False, methods=["POST"], permission_classes=[AllowAny])
    def sendRegisterVerifyEmail(self, request: Request) -> Response:
        """发送注册验证邮件"""
        if "username" not in request.data:
            return self.errUserResponse("", "账号不能为空")
        pattern1 = r"^[A-Za-z0-9\u4e00-\u9fa5]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$"
        if not re.match(pattern1, request.data.get("username")):
            return self.errUserResponse("", "账号必须为邮箱格式")
        username = request.data.get("username")
        if cache.get("EmailLock::" + username):
            return self.errUserResponse("", "请勿频繁操作，120s后再重新提交请求")
        user = User.objects.filter(username=request.data.get("username")).first()
        if not user:
            return self.errUserResponse("", "用户不存在，请前往注册")
        if user.is_verify_email:
            return self.errUserResponse("", "邮箱已验证，请直接登录")
        # 生成6位数字验证码
        email_code = "".join(str(random.randint(0, 9)) for _ in range(6))
        hash_object = hashlib.md5(email_code.encode())
        md5_hash = hash_object.hexdigest()
        cache.set(md5_hash, username, 600)

        lang = request.META.get('HTTP_LANGUAGE');
        verification_link = (
            CONFIG.get("app_url") + "/api/v3/core/users/verifyRegisterEmail/?code=" + md5_hash + "&lang=" + lang
        )  # 消息内容
        subject = "Mailbox verification"
        if lang == 'zh-cn' or lang == 'zh' :
            subject = "邮箱验证"
        if lang == 'zh-tw' or lang == 'tc' or lang == 'zh-CHT':
            subject = "郵箱驗證"

        result = mail.send_mail(
            subject = subject,  # 题目
            message = "注册验证",
            from_email=settings.DEFAULT_FROM_EMAIL,  # 发送者
            recipient_list=[username],  # 接收者邮件列表
            html_message=render_to_string(
                "email/verify_email.html",
                {"username": username, "verification_link": verification_link, "language": lang},
            ),
        )
        if result == 1:
            cache.set("EmailLock::" + username, 1, 120)
            return self.sucUserResponse("", "邮件发送成功")
        else:
            return self.errUserResponse("", "邮件发送失败")

    @action(detail=False, methods=["GET"], permission_classes=[AllowAny])
    def picCode(self, request: Request) -> Response:
        """图形验证码"""
        username = request.query_params.get("username")

        def check_code(width=120, height=30, char_length=5, font_file="Monaco.ttf", font_size=28):
            code = []
            img = Image.new(mode="RGB", size=(width, height), color=(255, 255, 255))
            draw = ImageDraw.Draw(img, mode="RGB")

            def rndChar():
                """
                生成随机字母
                :return:
                """
                return chr(random.randint(65, 90))

            def rndColor():
                """
                生成随机颜色
                :return:
                """
                return (random.randint(0, 255), random.randint(10, 255), random.randint(64, 255))

            # 写文字
            font = ImageFont.truetype(settings.BASE_DIR + '/' + font_file, font_size)
            for i in range(char_length):
                char = rndChar()
                code.append(char)
                h = random.randint(0, 4)
                draw.text([i * width / char_length, h], char, font=font, fill=rndColor())

            # 写干扰点
            for i in range(40):
                draw.point([random.randint(0, width), random.randint(0, height)], fill=rndColor())

            # 写干扰圆圈
            for i in range(40):
                draw.point([random.randint(0, width), random.randint(0, height)], fill=rndColor())
                x = random.randint(0, width)
                y = random.randint(0, height)
                draw.arc((x, y, x + 4, y + 4), 0, 90, fill=rndColor())

            # 画干扰线
            for i in range(5):
                x1 = random.randint(0, width)
                y1 = random.randint(0, height)
                x2 = random.randint(0, width)
                y2 = random.randint(0, height)

                draw.line((x1, y1, x2, y2), fill=rndColor())

            img = img.filter(ImageFilter.EDGE_ENHANCE_MORE)
            return img, "".join(code)

        # 调用poillow函数，生成图片
        img, code_string = check_code()
        print(code_string)
        verify_key = f"verify_pic_code_{username}"
        cache.set(verify_key, code_string, 600)
        # 创建内存中的文件
        stream = BytesIO()
        img.save(stream, "png")
        # return HttpResponse(stream.getvalue())
        response = HttpResponse(stream.getvalue(), content_type="image/png")
        response["Content-Disposition"] = "inline; filename=image.png"  # 可选设置文件名

        return response
        # return self.sucUserResponse(value, "请求成功")

    @action(detail=False, methods=["GET"], permission_classes=[AllowAny])
    def needCode(self, request: Request) -> Response:
        """登录是否需图像验证"""
        username = request.query_params.get("username")
        attempts_key = f"password_attempts_{username}"
        attempts = cache.get(attempts_key, 0)
        if attempts >= 4:
            return self.sucUserResponse("y", "请求成功")
        return self.sucUserResponse("n", "请求成功")

    def sucUserResponse(self, data="", msg="请求成功", code=1, status=200):
        response = {"data": data, "msg": msg, "code": code}
        return Response(response, status=status)

    def errUserResponse(self, data="", msg="请求成功", code=0, status=200):
        response = {"data": data, "msg": msg, "code": code}
        return Response(response, status=status)

    def limitRequest(self, request: Request):
        ip = request.META["HTTP_X_FORWARDED_FOR"]
        rq_num = cache.get(ip, 0)
        cache.set(ip, rq_num + 1,)
        if rq_num > 60:
            return True
        return False
