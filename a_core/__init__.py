from __future__ import absolute_import, unicode_literals
import os

# Can lock celery with log write permissions.
from a_core.corelogger import test_logger
log = test_logger()


# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
# from .octo_celery import app as celery_app
# __all__ = ['celery_app']