import os
import re
import glob
import datetime
import argparse
from elasticsearch import Elasticsearch, helpers
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("log_ingestion")

# Regular expression pattern to parse log entries
LOG_PATTERN = r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\s-\s(\w+)\s+\[(.*?)\]\s-\s(.*)'

def parse_log_line(line):
    """Parse a log line into its components using regex."""
    match = re.match(LOG_PATTERN, line)
    if match:
        timestamp_str, log_level, component, message = match.groups()
        
        # Parse timestamp
        try:
            timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
        except ValueError:
            timestamp = datetime.datetime.now()
            logger.warning(f"Failed to parse timestamp: {timestamp_str}")
        
        # Extract additional details from component if possible
        component_details = {}
        try:
            # Attempt to extract fields like myid, IP address, etc.
            myid_match = re.search(r'myid=(\d+)', component)
            if myid_match:
                component_details['myid'] = int(myid_match.group(1))
            
            ip_match = re.search(r'/(\d+\.\d+\.\d+\.\d+)', component)
            if ip_match:
                component_details['ip'] = ip_match.group(1)
            
            port_match = re.search(r':(\d+):', component)
            if port_match:
                component_details['port'] = int(port_match.group(1))
            
            class_match = re.search(r'(\w+(?:\$\w+)*)@', component)
            if class_match:
                component_details['class'] = class_match.group(1)
        except Exception as e:
            logger.warning(f"Error parsing component details: {e}")
        
        return {
            "@timestamp": timestamp,
            "level": log_level,
            "component": component,
            "message": message,
            **component_details
        }
    else:
        logger.warning(f"Failed to parse log line: {line[:50]}...")
        return None

def process_log_file(file_path):
    """Process a single log file and yield documents for Elasticsearch."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                log_entry = parse_log_line(line.strip())
                if log_entry:
                    # Add file metadata
                    log_entry['source'] = {
                        'file': os.path.basename(file_path),
                        'path': str(file_path),
                        'line': line_num
                    }
                    yield log_entry
    except Exception as e:
        logger.error(f"Error processing file {file_path}: {e}")

def get_elasticsearch_client(host='localhost', port=9200, user=None, password=None, ca_certs=None):
    """Create and return an Elasticsearch client."""
    es_hosts = [f"https://{host}:{port}"]
    
    connection_params = {}
    
    if ca_certs:
        connection_params["ca_certs"] = ca_certs
    else:
        # For development/testing only - disable certificate verification
        connection_params["verify_certs"] = False
        connection_params["ssl_show_warn"] = False
    
    if user and password:
        connection_params["http_auth"] = (user, password)
    
    return Elasticsearch(es_hosts, **connection_params)

def get_data_stream_name():
    """Generate data stream name with current date."""
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    return f"logs-{today}"

def create_data_stream_if_not_exists(es_client, data_stream_name):
    """Create the data stream if it doesn't already exist."""
    try:
        # Check if data stream exists
        es_client.indices.get_data_stream(name=data_stream_name)
        logger.info(f"Data stream {data_stream_name} already exists")
    except Exception:
        # Create data stream
        logger.info(f"Creating data stream: {data_stream_name}")
        try:
            es_client.indices.create_data_stream(name=data_stream_name)
            logger.info(f"Data stream {data_stream_name} created successfully")
        except Exception as e:
            logger.error(f"Error creating data stream: {e}")
            raise

def ingest_logs_to_elasticsearch(logs_dir, es_client, data_stream_name, batch_size=1000):
    """Process all log files and ingest into Elasticsearch."""
    files = list(Path(logs_dir).glob('*.log'))
    total_files = len(files)
    
    if total_files == 0:
        logger.warning(f"No log files found in {logs_dir}")
        return 0
    
    logger.info(f"Found {total_files} log files to process")
    
    def generate_actions():
        """Generate actions for bulk API."""
        for file_path in files:
            for doc in process_log_file(file_path):
                # For data streams, we use create operation type
                yield {
                    "_op_type": "create",
                    "_index": data_stream_name,
                    "_source": doc
                }
    
    # Use helpers.bulk for efficient indexing
    success, failed = 0, 0
    try:
        success, failed = helpers.bulk(
            es_client,
            generate_actions(),
            chunk_size=batch_size,
            request_timeout=60,
            raise_on_error=False
        )
        logger.info(f"Indexed {success} documents, {failed} failures")
    except Exception as e:
        logger.error(f"Error during bulk indexing: {e}")
    
    return success

def main():
    parser = argparse.ArgumentParser(description='Ingest log files into Elasticsearch')
    parser.add_argument('--logs_dir', type=str, required=True, help='Directory containing log files')
    parser.add_argument('--es_host', type=str, default='localhost', help='Elasticsearch host')
    parser.add_argument('--es_port', type=int, default=9200, help='Elasticsearch port')
    parser.add_argument('--es_user', type=str, help='Elasticsearch username')
    parser.add_argument('--es_pass', type=str, help='Elasticsearch password')
    parser.add_argument('--ca_certs', type=str, help='Path to CA certificate file')
    parser.add_argument('--batch_size', type=int, default=1000, help='Batch size for bulk indexing')
    
    args = parser.parse_args()
    
    try:
        # Connect to Elasticsearch
        logger.info(f"Connecting to Elasticsearch at {args.es_host}:{args.es_port}")
        es_client = get_elasticsearch_client(
            host=args.es_host, 
            port=args.es_port,
            user=args.es_user,
            password=args.es_pass,
            ca_certs=args.ca_certs
        )
        
        # Check connection
        if not es_client.ping():
            logger.error("Could not connect to Elasticsearch. Please check your connection settings.")
            return
        
        logger.info("Successfully connected to Elasticsearch")
        
        # Create data stream if not exists
        data_stream_name = get_data_stream_name()
        create_data_stream_if_not_exists(es_client, data_stream_name)
        
        # Ingest logs
        indexed_count = ingest_logs_to_elasticsearch(
            args.logs_dir, 
            es_client, 
            data_stream_name,
            batch_size=args.batch_size
        )
        
        logger.info(f"Completed log ingestion. Total documents indexed: {indexed_count}")
        
    except Exception as e:
        logger.error(f"Error during log ingestion: {e}")

if __name__ == "__main__":
    main()