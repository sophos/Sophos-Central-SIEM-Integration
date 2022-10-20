# Logging Configuration. Make sure to call before any import state directives
# marin@helpmesee.org
import logging
import logging.handlers
import datetime
import sys

DEBUG_FORMAT = "%(asctime)s\t%(levelname)s\t%(filename)s::%(funcName)s()\t%(message)s"

DEFAULT_FORMAT = "%(asctime)s\t%(levelname)s\t%(message)s"

logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).astimezone().isoformat(sep="T",timespec="milliseconds"))
  
logging.basicConfig(
    handlers=[
        #TODO logging.FileHandler(os.path.join(OUTPUT_DIR,"applog","rtpu_collector.log")),
        logging.StreamHandler(sys.stdout)
    ],
    level=logging.INFO,
    format=DEFAULT_FORMAT
)
