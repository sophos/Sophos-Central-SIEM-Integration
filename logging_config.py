# Logging Configuration. Make sure to call before any import state directives
# marin@helpmesee.org
import logging
import logging.handlers
import datetime
import sys
logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).astimezone().isoformat(sep="T",timespec="milliseconds"))
  
logging.basicConfig(
    handlers=[
        #TODO logging.FileHandler(os.path.join(OUTPUT_DIR,"applog","rtpu_collector.log")),
        logging.StreamHandler(sys.stdout)
    ],
    level=logging.INFO,
    format = "%(asctime)s\t%(levelname)s\t%(funcName)s()\t%(message)s")
