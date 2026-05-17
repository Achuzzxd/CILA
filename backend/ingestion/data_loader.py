import pandas as pd
import json
import logging
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

def load_data(file_path: str, file_format: str, chunk_size: int = 10000) -> Iterator[pd.DataFrame]:
    """
    Loads data from the given file path based on the specified format.
    Yields dataframes in chunks to support large files without OOM errors.
    """
    try:
        if file_format == 'csv':
            for chunk in pd.read_csv(file_path, chunksize=chunk_size):
                yield chunk
        elif file_format == 'json':
            # Try to read as lines first (common for logs), then standard JSON
            try:
                for chunk in pd.read_json(file_path, lines=True, chunksize=chunk_size):
                    yield chunk
            except ValueError:
                # If lines=True fails, try standard json (loads whole file)
                try:
                    df = pd.read_json(file_path)
                    yield df
                except Exception as e:
                    logger.error(f"JSON parsing error for {file_path}: {str(e)}")
        elif file_format == 'txt':
            # Text logs usually have custom formatting, but for now we read each line as a single column
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            df = pd.DataFrame({'raw_log_line': [line.strip() for line in lines if line.strip()]})
            yield df
        else:
            logger.warning(f"Unsupported file format: {file_format} for file {file_path}")
    except Exception as e:
        logger.error(f"Error loading file {file_path}: {str(e)}")
