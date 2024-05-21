FROM python:3.11-slim

RUN mkdir eXinakai
WORKDIR eXinakai

ADD requirements/prod.txt /eXinakai/requirements.txt
RUN pip install -r requirements.txt
#RUN apt-get update && apt-get install -y curl && apt-get clean

ADD . /eXinakai/
ADD .env.docker /eXinakai/.env

RUN mkdir log/

CMD sleep 10; python manage.py makemigrations; python manage.py migrate; python manage.py collectstatic --no-input; \
gunicorn core.wsgi:application -c /eXinakai/gunicorn.conf.py
