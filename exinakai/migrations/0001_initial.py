# Generated by Django 5.0.4 on 2024-06-28 13:22

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
                'ordering': ('-time_added',),
                'get_latest_by': ('-time_added',),
                'base_manager_name': 'storable',
                'default_manager_name': 'storable',
            },
            managers=[
                ('storable', django.db.models.manager.Manager()),
            ],
        ),
        migrations.CreateModel(
            name='PasswordsCollection',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=128, verbose_name='Название')),
                ('time_created', models.DateTimeField(auto_now_add=True, verbose_name='Время создания')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='Создатель', to=settings.AUTH_USER_MODEL, verbose_name='Создатель')),
                ('passwords', models.ManyToManyField(to='exinakai.password')),
            ],
            options={
                'verbose_name': 'Коллекция',
                'verbose_name_plural': 'Коллекции',
                'db_table': 'passwords_collection',
                'db_table_comment': 'Созданные пользователями коллекции паролей.',
                'ordering': ('time_created',),
                'get_latest_by': ('time_created',),
            },
        ),
        migrations.AddField(
            model_name='password',
            name='collection',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='Коллекция', to='exinakai.passwordscollection', verbose_name='Коллекция'),
        ),
        migrations.AddIndex(
            model_name='password',
            index=models.Index(fields=['note'], name='passwords_note_12e15a_idx'),
        ),
    ]
