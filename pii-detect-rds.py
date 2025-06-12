#!/usr/bin/env python3
"""
PII Detection for RDS/Aurora Databases

This script scans RDS/Aurora databases for PII data using Amazon Bedrock.
It supports both Aurora DB clusters and standard RDS DB instances.
"""

import mysql.connector 
import boto3
import json
import argparse
import time
from botocore.exceptions import ClientError
from datetime import datetime
from prompt import SYSTEM_PROMPT

NOVA_PRO_MODEL_ID = "amazon.nova-pro-v1:0"

# Constants for Bedrock models
def get_nova_model_id(region_name="ap-southeast-1"):
    """
    Get the appropriate Nova model ID based on the region name
    """
    if region_name.startswith("ap"):
        return f"apac.{NOVA_PRO_MODEL_ID}"
    elif region_name.startswith("eu"):
        return f"eu.{NOVA_PRO_MODEL_ID}"
    elif region_name.startswith("us"):
        return f"us.{NOVA_PRO_MODEL_ID}"
    else:
        return f"apac.{NOVA_PRO_MODEL_ID}"  # Default to APAC

def get_secret(secret_name, region_name="ap-southeast-1"):
    """
    Retrieve secret from AWS Secrets Manager
    """
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    try:
        # Get the secret value
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        # Handle exceptions
        print(f"Error retrieving secret: {e}")
        raise e
    else:
        # Decode and return the secret if successful
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            # If binary secret
            return json.loads(get_secret_value_response['SecretBinary'])

def get_databases(host, port, username, password):
    try:
        # Connect to server
        cnx = mysql.connector.connect(
            host=host,
            port=port,
            user=username,
            password=password)       
        # Get a cursor
        cur = cnx.cursor()      
        # Get the list of databases
        cur.execute("SHOW DATABASES")
        db_list = cur.fetchall()

        return db_list
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the connection
        if 'cnx' in locals() and cnx:
            cnx.close()
            #print("Database connection closed.")

def get_tables(host, port, username, password, db_name):
    try:
        # Connect to server
        cnx = mysql.connector.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            database=db_name
        )
        # Get a cursor
        cur = cnx.cursor()        
        # Get the list of tables
        cur.execute("SHOW TABLES")
        table_list = cur.fetchall()

        return table_list
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the connection
        if 'cnx' in locals() and cnx:
            cnx.close()
            #print("Database connection closed.")

def get_schema(host, port, username, password, db_name, table_name):
    try:
        # Connect to server
        cnx = mysql.connector.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            database=db_name
        )
        # Get a cursor
        cur = cnx.cursor()
        # Get the table schema
        cur.execute(f"DESCRIBE {table_name}")
        schema = cur.fetchall()

        return schema
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the connection
        if 'cnx' in locals() and cnx:
            cnx.close()
            #print("Database connection closed.")

def get_sample_data(host, port, username, password, db_name, table_name, sample_rate=0.1, limit=100):
    try:
        # Connect to server
        cnx = mysql.connector.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            database=db_name
        )
        # Get a cursor
        cur = cnx.cursor()

        """
        Query a table with sampling
        """
        # Get total count of records
        cur.execute(f"SELECT COUNT(*) FROM {table_name}")
        total_count = cur.fetchone()[0]
        
        # Calculate how many records to sample
        sample_size = min(max(1, total_count * sample_rate), limit)
        
        # Use MySQL's RAND() function for sampling
        query = f"""
            SELECT * FROM {table_name}
            ORDER BY RAND()
            LIMIT {sample_size}
        """
        cur.execute(query)
        sample_data = cur.fetchall()

        return sample_data, sample_size, total_count
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the connection
        if 'cnx' in locals() and cnx:
            cnx.close()
            #print("Database connection closed.")

def rds_detect_pii(sample_data, schema, region_name="ap-southeast-1"):
    try:
        # Create a Bedrock Runtime client
        client = boto3.client("bedrock-runtime", region_name=region_name)
    
        prompt = f"""Here is the sample data and schema of a specific database table.
    
        Sample Data:
        {sample_data}
        
        Table schema: 
        {schema}
    
        Detect PII categories in the provided data below, and follow the instruction to return the result in JSON format.
        """
        
        messages = [
            {
                "role": "user",
                "content": [{ "text": prompt }],
            }
        ]
        system = [{ "text": SYSTEM_PROMPT }]
        inf_params = {"maxTokens": 300, "topP": 0.1, "temperature": 0.3}
        
        model_id = get_nova_model_id(region_name)
        response = client.converse(
            modelId=model_id, messages=messages, system=system, inferenceConfig=inf_params
        )
    
        return response
    except (ClientError, Exception) as e:
        error_msg = f"ERROR: Can't invoke '{model_id}'. Reason: {e}"
        print(error_msg)
        return error_msg

def save_list_to_jsonl(data_list, file_path):
    """
    Save a list of items to a JSONL file.
    Each item in the list will be written as a separate JSON object on its own line.

    Args:
        data_list: List of objects to save (each object should be JSON serializable)
        file_path: Path to the output JSONL file
    """
    with open(file_path, 'w') as f:
        for item in data_list:
            # Convert each item to a JSON string and write it with a newline
            f.write(json.dumps(item) + '\n')

def process_single_table(host, port, username, password, db_name, table_name, 
                      region_name, db_identifier, source_type, sample_rate, limit, delay, results):
    """
    Process a single table for PII detection
    """
    result = {}
    result['source_type'] = source_type  # 'RDS' or 'Aurora'
    result['region'] = region_name
    result['db_identifier'] = db_identifier
    result['db_name'] = db_name
    result['table_name'] = table_name
    
    # Get table schema and sample data
    schema = get_schema(host, port, username, password, db_name, table_name)
    sample_data, sample_size, total_count = get_sample_data(host, port, username, password, db_name, table_name, sample_rate, limit)

    if len(schema) > 0 and len(sample_data) > 0:
        result['sample_size'] = sample_size
        result['total_row'] = total_count
        
        # Detect PII in the sample data
        model_response = rds_detect_pii(str(sample_data), str(schema), region_name)
        if isinstance(model_response, dict):
            pii_result = json.loads(model_response['output']['message']['content'][0]['text'])
            result.update(pii_result)
            result['input_token'] = model_response['usage']['inputTokens']
            result['output_token'] = model_response['usage']['outputTokens']
            result['timestamp'] = datetime.now().isoformat()
            
            print(json.dumps(result, indent=2))
            print(f"Input Token: {model_response['usage']['inputTokens']}")
            print(f"Output Token: {model_response['usage']['outputTokens']}")
    
            results.append(result.copy())                        
        elif isinstance(model_response, str):
            result['error'] = model_response
            result['timestamp'] = datetime.now().isoformat()
            results.append(result.copy())

def process_database(host, port, username, password, db_name, 
                   region_name, db_identifier, source_type, sample_rate, limit, delay, results):
    """
    Process all tables in a database for PII detection
    """
    # Get list of tables in the database
    table_list = get_tables(host, port, username, password, db_name)
    for table in table_list:
        table_name = table[0]
        process_single_table(host, port, username, password, db_name, table_name, 
                          region_name, db_identifier, source_type, sample_rate, limit, 
                          delay, results)
        time.sleep(delay)

def main():
    parser = argparse.ArgumentParser(description='PII Detection for RDS/Aurora Databases')
    parser.add_argument('--db-identifier', required=True, help='RDS DB instance identifier or Aurora DB cluster identifier')
    parser.add_argument('--db-type', choices=['rds', 'aurora'], required=True, help='Type of database: "rds" for RDS DB instance, "aurora" for Aurora DB cluster')
    parser.add_argument('--port', type=int, default=3306, help='Database port (default: 3306)')
    parser.add_argument('--secret-name', required=True, help='AWS Secrets Manager secret name containing database credentials')
    parser.add_argument('--region-name', default='ap-southeast-1', help='AWS region name (default: ap-southeast-1)')
    parser.add_argument('--db-name', help='Specific database name to scan (optional)')
    parser.add_argument('--table-name', help='Specific table name to scan (requires --db-name)')
    parser.add_argument('--output', default='pii-detect-rds.jsonl', help='Output file path (default: pii-detect-rds.jsonl)')
    parser.add_argument('--sample-rate', type=float, default=0.2, help='Fraction of records to sample per table (default: 0.2)')
    parser.add_argument('--limit', type=int, default=10000, help='Maximum number of records to sample per table (default: 10000)')
    parser.add_argument('--delay', type=int, default=5, help='Delay between API calls in seconds (default: 5)')
    
    args = parser.parse_args()
    
    db_identifier = args.db_identifier
    db_type = args.db_type
    db_port = args.port
    secret_name = args.secret_name
    region_name = args.region_name
    db_name = args.db_name
    table_name = args.table_name
    output_file = args.output
    sample_rate = args.sample_rate
    limit = args.limit
    delay = args.delay
    
    # Check if table_name is provided without db_name
    if table_name and not db_name:
        print("Error: --table-name requires --db-name to be specified")
        return

    # Get database endpoint based on db-type
    rds_client = boto3.client('rds', region_name=region_name)
    
    try:
        if db_type == 'aurora':
            # For Aurora DB clusters
            response = rds_client.describe_db_clusters(DBClusterIdentifier=db_identifier)
            db_endpoint = response['DBClusters'][0]['ReaderEndpoint']
            source_type = 'Aurora'
        else:
            # For RDS DB instances
            response = rds_client.describe_db_instances(DBInstanceIdentifier=db_identifier)
            db_endpoint = response['DBInstances'][0]['Endpoint']['Address']
            source_type = 'RDS'
    except ClientError as e:
        print(f"Error retrieving database information: {e}")
        return

    # Get database credentials from Secrets Manager
    secret = get_secret(secret_name, region_name) 

    # Extract connection parameters from the secret
    host = secret.get('host', db_endpoint)  # Use db_endpoint if host is not in the secret
    port = secret.get('port', db_port)  # Use command-line port if not in secret
    username = secret.get('username')
    password = secret.get('password')

    results = []
    
    # If db_name is provided, check if it exists
    if db_name:
        db_list = get_databases(host, port, username, password)
        db_names = [db[0] for db in db_list]
        if db_name not in db_names:
            print(f"\nError: Database '{db_name}' does not exist.")
            return
            
        # If table_name is provided, check if it exists
        if table_name:
            table_list = get_tables(host, port, username, password, db_name)
            table_names = [table[0] for table in table_list]
            if table_name not in table_names:
                print(f"\nError: Table '{table_name}' does not exist in database '{db_name}'.")
                return

    # Prepare summary information for confirmation
    print("\nPII Detection Summary:")
    print(f"- DB Type: {source_type}")
    print(f"- DB Identifier: {db_identifier}")
    print(f"- DB Endpoint: {db_endpoint}")
    print(f"- DB Port: {port}")
    print(f"- Region: {region_name}")
    print(f"- Sample Rate: {sample_rate}")
    print(f"- Sample Limit: {limit} records per table")
    
    if db_name and table_name:
        print(f"- Target: Single table '{table_name}' in database '{db_name}'")
    elif db_name:
        print(f"- Target: All tables in database '{db_name}'")
    else:
        print(f"- Target: All tables in all user databases")
    
    # Ask for confirmation
    confirm = input("\nDo you want to proceed with PII detection? (y/n): ").strip().lower()
    if confirm != 'y' and confirm != 'yes':
        print("PII detection cancelled.")
        return
        
    print("\nStarting PII detection...\n")

    # If specific db_name is provided
    if db_name:
        # If specific table_name is also provided
        if table_name:
            process_single_table(host, port, username, password, db_name, table_name, 
                                region_name, db_identifier, source_type, sample_rate, limit, 
                                delay, results)
        else:
            # Process all tables in the specified database
            process_database(host, port, username, password, db_name, 
                           region_name, db_identifier, source_type, sample_rate, limit, 
                           delay, results)
    else:
        # Get list of databases and process all
        db_list = get_databases(host, port, username, password)
        for db in db_list:
            # Skip system databases
            if db not in [('information_schema',), ('mysql',), ('performance_schema',), ('sys',)]:
                process_database(host, port, username, password, db[0], 
                               region_name, db_identifier, source_type, sample_rate, limit, 
                               delay, results)

    # Save results to JSONL file
    save_list_to_jsonl(results, output_file)
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
