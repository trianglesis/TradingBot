import datetime
import logging
import os


now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
place = os.path.dirname(os.path.abspath(__file__))


def test_logger():
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)

    log_name = "/var/log/tradingbot/core.log"
    # Extra detailed logging to file:
    rf_handler = logging.FileHandler(log_name, mode='a', encoding='utf-8')
    rf_handler.setLevel(logging.DEBUG)
    # Extra detailed logging to console:
    f_format = logging.Formatter(
        '{asctime:<24}'
        '{levelname:<8}'
        '{filename:<20}'
        '{funcName:<22}'
        'L:{lineno:<6}'
        '{message:8s}',
        style='{'
    )
    rf_handler.setFormatter(f_format)
    log.addHandler(rf_handler)
    return log
