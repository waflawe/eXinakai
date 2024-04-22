# Generated by Django 5.0.4 on 2024-04-22 16:24

import django.db.models.deletion
import django.db.models.manager
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Password',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('note', models.CharField(max_length=256, verbose_name='Примета')),
                ('password', models.CharField(max_length=512, verbose_name='Пароль')),
                ('time_added', models.DateTimeField(auto_now_add=True, verbose_name='Время добавления')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='Владелец', to=settings.AUTH_USER_MODEL, verbose_name='Владелец')),
            ],
            options={
                'verbose_name': 'Пароль',
                'verbose_name_plural': 'Пароли',
                'db_table': 'passwords',
                'db_table_comment': 'Сохраненные пользователем пароли.',
                'ordering': ('time_added',),
                'get_latest_by': ('time_added',),
                'base_manager_name': 'storable',
                'default_manager_name': 'storable',
                'indexes': [models.Index(fields=['note'], name='passwords_note_12e15a_idx')],
            },
            managers=[
                ('storable', django.db.models.manager.Manager()),
            ],
        ),
    ]
