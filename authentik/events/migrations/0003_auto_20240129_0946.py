# Generated by Django 3.2.6 on 2024-01-29 09:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentik_core', '0034_user_is_send_email'),
        ('authentik_events', '0002_alter_notificationtransport_mode'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='event',
            options={'verbose_name': '事件', 'verbose_name_plural': '事件'},
        ),
        migrations.AlterModelOptions(
            name='notification',
            options={'verbose_name': '通知', 'verbose_name_plural': '通知'},
        ),
        migrations.AlterModelOptions(
            name='notificationrule',
            options={'verbose_name': '通知规则', 'verbose_name_plural': '通知规则'},
        ),
        migrations.AlterModelOptions(
            name='notificationtransport',
            options={'verbose_name': '通知传输', 'verbose_name_plural': '通知传输'},
        ),
        migrations.AlterModelOptions(
            name='notificationwebhookmapping',
            options={'verbose_name': 'Webhook 映射', 'verbose_name_plural': 'Webhook 映射'},
        ),
        migrations.AlterField(
            model_name='notification',
            name='severity',
            field=models.TextField(choices=[('notice', '通知'), ('warning', '警告'), ('alert', '注意')]),
        ),
        migrations.AlterField(
            model_name='notificationrule',
            name='group',
            field=models.ForeignKey(blank=True, help_text='定义此通知应该发送到哪些用户组。如果留空，则不会发送通知。', null=True, on_delete=django.db.models.deletion.SET_NULL, to='authentik_core.group'),
        ),
        migrations.AlterField(
            model_name='notificationrule',
            name='severity',
            field=models.TextField(choices=[('notice', '通知'), ('warning', '警告'), ('alert', '注意')], default='notice', help_text='控制被创建的通知的严重性级别。'),
        ),
        migrations.AlterField(
            model_name='notificationrule',
            name='transports',
            field=models.ManyToManyField(blank=True, help_text='选择应使用哪些传输方式来通知用户。如果未选择任何内容，则通知将仅显示在 authentik UI 中。', to='authentik_events.NotificationTransport'),
        ),
        migrations.AlterField(
            model_name='notificationtransport',
            name='mode',
            field=models.TextField(choices=[('local', 'authentik 内置通知'), ('webhook', '通用 Webhook'), ('webhook_slack', 'Slack Webhook（Slack/Discord）'), ('email', '电子邮箱')], default='local'),
        ),
        migrations.AlterField(
            model_name='notificationtransport',
            name='send_once',
            field=models.BooleanField(default=False, help_text='仅发送一次通知，例如在向聊天频道发送 Webhook 时。'),
        ),
    ]