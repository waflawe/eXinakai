# Generated by Django 5.0.4 on 2024-05-09 22:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_exinakaiuser_is_2fa_enabled'),
    ]

    operations = [
        migrations.AlterField(
            model_name='exinakaiuser',
            name='is_2fa_enabled',
            field=models.BooleanField(default=True, verbose_name='Включена ли 2FA'),
        ),
    ]