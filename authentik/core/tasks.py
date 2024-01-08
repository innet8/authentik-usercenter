"""authentik core tasks"""
from datetime import datetime, timedelta

from django.contrib.sessions.backends.cache import KEY_PREFIX
from django.core.cache import cache
from django.utils.timezone import now
from structlog.stdlib import get_logger
import subprocess
from django.core import mail
from django.conf import settings
from django.template.loader import render_to_string

from authentik.core.models import (
    USER_ATTRIBUTE_EXPIRES,
    USER_ATTRIBUTE_GENERATED,
    AuthenticatedSession,
    ExpiringModel,
    User,
)
from authentik.events.monitored_tasks import (
    MonitoredTask,
    TaskResult,
    TaskResultStatus,
    prefill_task,
)
from authentik.root.celery import CELERY_APP

LOGGER = get_logger()


@CELERY_APP.task(bind=True, base=MonitoredTask)
@prefill_task
def clean_expired_models(self: MonitoredTask):
    """Remove expired objects"""
    messages = []
    for cls in ExpiringModel.__subclasses__():
        cls: ExpiringModel
        objects = (
            cls.objects.all().exclude(expiring=False).exclude(expiring=True, expires__gt=now())
        )
        amount = objects.count()
        for obj in objects:
            obj.expire_action()
        LOGGER.debug("Expired models", model=cls, amount=amount)
        messages.append(f"Expired {amount} {cls._meta.verbose_name_plural}")
    # Special case
    amount = 0
    for session in AuthenticatedSession.objects.all():
        cache_key = f"{KEY_PREFIX}{session.session_key}"
        value = None
        try:
            value = cache.get(cache_key)
        # pylint: disable=broad-except
        except Exception as exc:
            LOGGER.debug("Failed to get session from cache", exc=exc)
        if not value:
            session.delete()
            amount += 1
    LOGGER.debug("Expired sessions", model=AuthenticatedSession, amount=amount)
    messages.append(f"Expired {amount} {AuthenticatedSession._meta.verbose_name_plural}")
    self.set_status(TaskResult(TaskResultStatus.SUCCESSFUL, messages))


@CELERY_APP.task(bind=True, base=MonitoredTask)
@prefill_task
def clean_temporary_users(self: MonitoredTask):
    """Remove temporary users created by SAML Sources"""
    _now = datetime.now()
    messages = []
    deleted_users = 0
    for user in User.objects.filter(**{f"attributes__{USER_ATTRIBUTE_GENERATED}": True}):
        if not user.attributes.get(USER_ATTRIBUTE_EXPIRES):
            continue
        delta: timedelta = _now - datetime.fromtimestamp(
            user.attributes.get(USER_ATTRIBUTE_EXPIRES)
        )
        if delta.total_seconds() > 0:
            LOGGER.debug("User is expired and will be deleted.", user=user, delta=delta)
            user.delete()
            deleted_users += 1
    messages.append(f"Successfully deleted {deleted_users} users.")
    self.set_status(TaskResult(TaskResultStatus.SUCCESSFUL, messages))

@CELERY_APP.task(bind=True, base=MonitoredTask)
@prefill_task
def detection_password(self: MonitoredTask):
    """Sources"""
    # DOTO 打个文件进行测试
    subprocess.run("echo '1' > test.text", shell=True, capture_output=True, text=True)
    #
    for user in User.objects.filter(password='', is_send_email=False):
        if user.email:
            source = user.path
            source_all = source
            if source == "pwf":
                source = "PWF"
                source_all = "Pocket Wallet Finance"
            result = mail.send_mail(
                subject="Account Security Upgrade Notice",  # 题目
                message="Account Security Upgrade Notice",
                from_email=settings.DEFAULT_FROM_EMAIL,  # 发送者
                recipient_list=[user.email],  # 接收者邮件列表
                html_message=render_to_string(
                    "email/upgrade_notification.html",
                    {"source": source, "source_all": source_all},
                ),
            )
            if result == 1:
                user.is_send_email = True
                user.save()
            else:
                rq_num = cache.get(user.email, 0)
                cache.set(user.email, rq_num + 1)
                if rq_num > 3:
                    user.is_send_email = True
                    user.save()
