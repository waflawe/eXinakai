# Generated by Django 5.0.4 on 2024-04-22 16:24

import django.contrib.auth.validators
import users.models
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ExinakaiUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('username', models.CharField(error_messages={'unique': 'Пользователь с таким именем уже существует.'}, help_text='Обязателен. Не более 64 символов. Буквы, цифры, @/./+/-/_.', max_length=64, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='Имя пользователя')),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='Почта')),
                ('avatar', models.ImageField(default='default-user-icon.jpg', upload_to=users.models.get_uploaded_avatar_path, verbose_name='Аватарка')),
                ('timezone', models.CharField(default='Europe/London', max_length=64, verbose_name='Временная зона')),
                ('date_joined', models.DateTimeField(auto_now_add=True, verbose_name='Время регистрации')),
            ],
            options={
                'verbose_name': 'Пользователь',
                'verbose_name_plural': 'Пользователи',
                'db_table': 'user',
            },
        ),
    ]
