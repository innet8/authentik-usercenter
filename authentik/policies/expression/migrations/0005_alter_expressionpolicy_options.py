# Generated by Django 3.2.6 on 2024-01-29 09:46

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentik_policies_expression', '0004_expressionpolicy_authentik_p_policy__fb6feb_idx'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='expressionpolicy',
            options={'verbose_name': '表达式策略', 'verbose_name_plural': '表达式策略'},
        ),
    ]
