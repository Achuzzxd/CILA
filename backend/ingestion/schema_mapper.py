import pandas as pd
import logging

logger = logging.getLogger(__name__)

UNIFIED_SCHEMA = ['timestamp', 'user', 'event', 'ip', 'status', 'source']

KEYWORD_MAP = {
    'timestamp': ["timestamp", "time", "date", "event_time", "logged_at", "creation_time"],
    'user': ["user", "username", "userid", "user_id", "actor", "account", "usr"],
    'event': ["event", "action", "activity", "operation", "event_name", "log_event", "message"],
    'ip': ["ip", "ip_address", "source_ip", "client_ip"],
    'status': ["status", "result", "outcome", "state", "resultado"]
}

def standardize_schema(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardizes the DataFrame columns to match the UNIFIED_SCHEMA using dynamic matching.
    Implements a fallback to raw text strings if the row mapping fails to find an event.
    """
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_SCHEMA)
        
    df = df.copy()
    
    # Store string representations for robust fallback BEFORE dropping columns
    raw_strings = [str(r) for r in df.to_dict(orient='records')]

    if 'raw_log_line' in df.columns:
        df['event'] = df['raw_log_line']
        df.drop(columns=['raw_log_line'], inplace=True)
    
    raw_columns = df.columns.tolist()
    rename_mapping = {}
    
    # Keyword matching logic
    for col in raw_columns:
        col_lower = str(col).lower()
        matched = False
        # Exact match inside keyword bins
        for target_field, keywords in KEYWORD_MAP.items():
            if col_lower in keywords:
                rename_mapping[col] = target_field
                matched = True
                break
        
        # If no exact match, try partial match within keywords
        if not matched:
            for target_field, keywords in KEYWORD_MAP.items():
                if any(kw in col_lower for kw in keywords):
                    rename_mapping[col] = target_field
                    break

    df.rename(columns=rename_mapping, inplace=True)
    
    # Initialize structurally missing columns
    for col in UNIFIED_SCHEMA:
        if col not in df.columns:
            df[col] = None
            
    # Deduplicate columns safely if multiple columns mapped to identical final keys
    df = df.loc[:, ~df.columns.duplicated()]
    
    # Re-verify initialization
    for col in UNIFIED_SCHEMA:
        if col not in df.columns:
            df[col] = None

    # FALLBACK LOGIC: If 'event' is empty, inject the string representation of the unmapped row
    df['__raw__'] = raw_strings
    is_empty_mask = df['event'].isnull() | (df['event'].astype(str).str.strip() == '') | (df['event'].astype(str).str.lower() == 'none')
    
    num_fallbacks = is_empty_mask.sum()
    if num_fallbacks > 0:
        logger.debug(f"Applying fallback raw string dumping for {num_fallbacks} rows.")
        df.loc[is_empty_mask, 'event'] = df.loc[is_empty_mask, '__raw__']
        
    df.drop(columns=['__raw__'], inplace=True)
            
    return df[UNIFIED_SCHEMA]
