import os

def detect_format(file_path: str) -> str:
    """
    Detects the format of the file based on its extension.
    Returns: 'csv', 'json', 'txt' or 'unknown'
    """
    _, ext = os.path.splitext(file_path)
    ext = ext.lower().replace('.', '')
    
    if ext in ['csv', 'json', 'txt']:
        return ext
    return 'unknown'
