import factory
import faker

from django.contrib.auth import get_user_model
from exinakai.models import PasswordsCollection, Password

User = get_user_model()


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User

    username = factory.LazyFunction(lambda: faker.Faker().user_name())
    email = factory.Faker("email")
    password = factory.Faker("password")


class PasswordsCollectionFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = PasswordsCollection

    name = factory.LazyFunction(lambda: faker.Faker().user_name())
    owner = factory.SubFactory(UserFactory)


class PasswordFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Password

    note = factory.LazyFunction(lambda: faker.Faker().user_name())
    owner = factory.SubFactory(UserFactory)
    collection = factory.SubFactory(PasswordsCollectionFactory)
    password = factory.Faker("password")
