import pandas as pd
import numpy as np
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

def clean_and_validate(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Cleans the dataframe, enforces JSON serialization safety, and splits by relaxed validity.
    """
    if df.empty:
        return df.copy(), df.copy()

    df.dropna(how='all', inplace=True)
    df.drop_duplicates(inplace=True)
    
    # Text normalization
    for col in ['user', 'status']:
        if col in df.columns:
            df[col] = df[col].astype(str).str.lower().replace(['none', 'nan'], None)
            
    if 'event' in df.columns:
        df['event'] = df['event'].astype(str).replace(['none', 'nan'], None)
            
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].apply(lambda x: x if pd.notnull(x) and str(x).strip() != '' else None)

    # Normalize timestamps rigorously
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        valid_ts_mask = df['timestamp'].notnull()
        df.loc[valid_ts_mask, 'timestamp'] = df.loc[valid_ts_mask, 'timestamp'].dt.strftime('%Y-%m-%dT%H:%M:%S%z')
        # Absolute coercion of NaT to None required for JSON serializer
        df['timestamp'] = df['timestamp'].replace({pd.NaT: None})
        
    # Scour everything to ensure numpy types (np.nan, NaT) are replaced with None
    df = df.replace({np.nan: None, pd.NaT: None})

    # Relaxed Validation: ONLY event must exist. timestamp and user can be None.
    invalid_mask = df['event'].isnull() | (df['event'].astype(str).str.strip() == '') | (df['event'].astype(str).str.lower() == 'none')
    
    valid_df = df[~invalid_mask].copy()
    invalid_df = df[invalid_mask].copy()

    return valid_df, invalid_df
