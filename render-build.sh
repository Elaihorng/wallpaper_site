#!/usr/bin/env bash
set -e

pip install -r requirements.txt

python manage.py migrate --noinput
python manage.py collectstatic --noinput

# Create superuser automatically if not exists
python manage.py createsuperuser --noinput || true
