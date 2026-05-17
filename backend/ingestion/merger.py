import os
import json
import logging
import pandas as pd

from .format_detector import detect_format
from .data_loader import load_data
from .schema_mapper import standardize_schema
from .validator import clean_and_validate

logger = logging.getLogger(__name__)

def merge_datasets(input_dir: str, output_dir: str):
    """
    Processes all datasets via chunks and output unified JSON. 
    Memory footprint minimized via native dictionary persistence.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    all_valid_logs = []
    all_invalid_logs = []
    
    total_processed = 0
    total_valid = 0
    total_invalid = 0

    if not os.path.exists(input_dir):
        logger.error(f"Input directory does not exist: {input_dir}")
        return

    for root, dirs, files in os.walk(input_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            if os.path.isfile(filepath):
                logger.info(f"Processing file: {filename}")
                
                file_format = detect_format(filepath)
                if file_format == 'unknown':
                    logger.warning(f"Skipping unknown format file: {filename}")
                    continue
                    
                chunk_iterator = load_data(filepath, file_format)
                if chunk_iterator is None:
                    continue
                
                file_processed, file_valid, file_invalid = 0, 0, 0
                
                # Process file iteratively to manage vast datasets
                for df in chunk_iterator:
                    if df is None or df.empty:
                        continue
                        
                    raw_count = len(df)
                    file_processed += raw_count
                    
                    df = standardize_schema(df)
                    df['source'] = filename
                    
                    valid_df, invalid_df = clean_and_validate(df)
                    
                    file_valid += len(valid_df)
                    file_invalid += len(invalid_df)
                    
                    # Convert to native python primitive dicts 
                    if not valid_df.empty:
                        # Extra safeguard: where replaces lingering Float NaNs missed prior
                        valid_df = valid_df.where(pd.notnull(valid_df), None)
                        all_valid_logs.extend(valid_df.to_dict(orient='records'))
                        
                    if not invalid_df.empty:
                        invalid_df = invalid_df.where(pd.notnull(invalid_df), None)
                        all_invalid_logs.extend(invalid_df.to_dict(orient='records'))

                logger.info(f"File {filename}: {file_valid} valid, {file_invalid} invalid.")
                total_processed += file_processed
                total_valid += file_valid
                total_invalid += file_invalid

    # Save to disk using standard json
    valid_out = os.path.join(output_dir, 'all_logs.json')
    if all_valid_logs:
        with open(valid_out, 'w', encoding='utf-8') as f:
            json.dump(all_valid_logs, f, indent=2, default=str)
        logger.info(f"Saved {len(all_valid_logs)} valid records to {valid_out}")
    else:
        logger.warning("No valid records found to merge.")
        with open(valid_out, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)

    invalid_out = os.path.join(output_dir, 'invalid_logs.json')
    if all_invalid_logs:
        with open(invalid_out, 'w', encoding='utf-8') as f:
            json.dump(all_invalid_logs, f, indent=2, default=str)
        logger.info(f"Saved {len(all_invalid_logs)} invalid records to {invalid_out}")
    else:
        with open(invalid_out, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)

    logger.info(f"Ingestion summary: Processed={total_processed}, Valid={total_valid}, Invalid={total_invalid}")
