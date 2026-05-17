# Cloud-Based Intelligent Log Anomaly Detection System (CLIA)

CLIA is a production-level SIEM-like system designed to ingest, parse, and analyze cloud and system logs to detect anomalies and classify potential security threats using Machine Learning.

## Features

- **Multi-Source Log Ingestion**: Support for JSON/CSV logs (CloudTrail, Syslog, etc.).
- **Automated Log Parsing**: Tokenization and template extraction.
- **Intelligent Anomaly Detection**: Unsupervised learning for outlier detection.
- **Threat Classification**: Supervised modules for categorizing detected anomalies.
- **Real-time Dashboard**: Streamlit-based visualization and reporting.

## Tech Stack

- **Backend**: Python (FastAPI)
- **Machine Learning**: Scikit-Learn
- **Database**: MongoDB / PostgreSQL
- **Frontend**: Streamlit

## Project Structure

```text
CLIA/
├── backend/          # API, Parsing, Detection, and Classification logic
├── frontend/         # Streamlit dashboard and UI components
├── models/           # Trained models and preprocessing pipelines
├── data/             # Raw, parsed, and processed log datasets
├── database/         # Database schemas and query logic
├── scripts/          # Ingestion and training automation scripts
├── config/           # Global configuration files
├── logs/             # System and application logs
├── outputs/          # Model outputs and intermediate results
└── reports/          # Security and performance reports
```

## Getting Started

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd CLIA
   ```

2. **Set up environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Run the Backend**:
   ```bash
   uvicorn backend.api.main:app --reload
   ```

4. **Run the Frontend**:
   Open in your browser
   
   http://127.0.0.1:8000/
   

## License

MIT
