import os
import sys
import logging

# Ensure backend module can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.ingestion.merger import merge_datasets

def setup_logging():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    log_dir = os.path.join(project_root, "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    log_file = os.path.join(log_dir, 'ingestion.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

def main():
    logger = setup_logging()
    
    # Dirs based on project root
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    input_dir = os.path.join(project_root, 'data', 'raw_logs')
    output_dir = os.path.join(project_root, 'data', 'unified_logs')
    
    logger.info("Starting Data Ingestion Pipeline...")
    logger.info(f"Input directory: {input_dir}")
    logger.info(f"Output directory: {output_dir}")
    
    # Ensure input_dir exists so we don't just error out silently
    if not os.path.exists(input_dir):
        os.makedirs(input_dir)
        logger.warning(f"Created empty input directory {input_dir}. Please place raw datasets here.")
    
    try:
        merge_datasets(input_dir, output_dir)
        logger.info("Ingestion Pipeline completed successfully.")
    except Exception as e:
        logger.error(f"Pipeline failed with error: {str(e)}", exc_info=True)

if __name__ == '__main__':
    main()
