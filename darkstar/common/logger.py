import logging


class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "\x1b[1m%(asctime)s [%(levelname)s]\x1b[0m - %(name)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def setup_logger():
    ColorfulHandler = logging.StreamHandler()
    ColorfulHandler.setFormatter(CustomFormatter())

    logging.addLevelName(logging.ERROR, "ERRR")
    logging.addLevelName(logging.WARNING, "WARN")

    logging.basicConfig(level=logging.INFO, handlers=[ColorfulHandler])
