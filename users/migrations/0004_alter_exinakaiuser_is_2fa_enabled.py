# Generated by Django 5.0.4 on 2024-05-09 22:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_alter_exinakaiuser_is_2fa_enabled'),
    ]

    operations = [
        migrations.AlterField(
            model_name='exinakaiuser',
            name='is_2fa_enabled',
            field=models.BooleanField(default=False, verbose_name='Включена ли 2FA'),
        ),
    ]
