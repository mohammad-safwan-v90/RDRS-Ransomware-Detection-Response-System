"""
Logging Setup for RDRS
Uses Loguru if available, or Python standard logging fallback.
"""

import sys
import os
import logging

try:
    from loguru import logger as loguru_logger
    HAS_LOGURU = True
except ImportError:
    HAS_LOGURU = False


class RDRSLogger:
    def __init__(self, log_dir: str = "logs"):
        self.log_file = os.path.join(log_dir, "rdrs_audit.log")
        file_logging_error = None
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError as ex:
            file_logging_error = ex

        if HAS_LOGURU:
            loguru_logger.remove()
            # Add stdout sink for INFO and WARNING
            loguru_logger.add(
                sys.stdout,
                format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
                level="INFO",
                filter=lambda record: record["level"].no < 40  # Less than ERROR (40)
            )
            # Add stderr sink for ERROR and CRITICAL
            loguru_logger.add(
                sys.stderr,
                format="<red>{time:YYYY-MM-DD HH:mm:ss}</red> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
                level="ERROR"
            )
            if file_logging_error is None:
                try:
                    loguru_logger.add(self.log_file, rotation="10 MB", level="DEBUG", encoding="utf-8")
                except Exception as ex:
                    file_logging_error = ex
            self._logger = loguru_logger
        else:
            self._logger = logging.getLogger("RDRS")
            self._logger.setLevel(logging.DEBUG)
            self._logger.propagate = False
            if not self._logger.handlers:
                stdout_handler = logging.StreamHandler(sys.stdout)
                stdout_handler.setLevel(logging.INFO)
                stdout_handler.addFilter(lambda record: record.levelno < logging.ERROR)

                stderr_handler = logging.StreamHandler(sys.stderr)
                stderr_handler.setLevel(logging.ERROR)

                formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)s - %(message)s')
                stdout_handler.setFormatter(formatter)
                stderr_handler.setFormatter(formatter)

                self._logger.addHandler(stdout_handler)
                self._logger.addHandler(stderr_handler)

                if file_logging_error is None:
                    try:
                        file_handler = logging.FileHandler(self.log_file, encoding="utf-8")
                        file_handler.setFormatter(formatter)
                        self._logger.addHandler(file_handler)
                    except OSError as ex:
                        file_logging_error = ex

        if file_logging_error is not None:
            sys.stderr.write(f"[RDRS Logger Warning] File logging disabled ({self.log_file}): {file_logging_error}\n")

    def info(self, msg: str):
        self._logger.info(msg)

    def warning(self, msg: str):
        self._logger.warning(msg)

    def error(self, msg: str):
        self._logger.error(msg)

    def exception(self, msg: str):
        self._logger.exception(msg)


logger = RDRSLogger()

