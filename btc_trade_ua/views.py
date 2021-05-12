import logging
from django.http import HttpResponse

log = logging.getLogger("a_core.corelogger")


def index(request):
    log.debug(f'debug: request{ request}')
    log.info(f'info: request{ request}')
    log.warning(f'warning: request{ request}')
    log.critical(f'critical: request{ request}')
    return HttpResponse("Hello, world. You're at the BTC TRADE UA")
