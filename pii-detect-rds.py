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
def get_nova_model_id(region_name="eu-central-1"):
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
        return f"eu.{NOVA_PRO_MODEL_ID}"  # Default to EU

def get_secret(secret_name, region_name="eu-central-1"):
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

def get_databases(cnx):
    cur = cnx.cursor()      
    cur.execute("SHOW DATABASES")
    db_list = cur.fetchall()
    cur.close()
    return db_list

def get_tables(cnx, db_name):
    cnx.database = db_name
    cur = cnx.cursor()        
    cur.execute("SHOW TABLES")
    table_list = cur.fetchall()
    cur.close()
    return table_list

def get_schema(cnx, db_name, table_name):
    cnx.database = db_name
    cur = cnx.cursor()
    cur.execute(f"DESCRIBE {table_name}")
    schema = cur.fetchall()
    cur.close()
    return schema

def get_sample_data(cnx, db_name, table_name, sample_rate=0.1, limit=100):
    cnx.database = db_name
    cur = cnx.cursor()

    # Get total count of records
    cur.execute(f"SELECT COUNT(*) FROM {table_name}")
    total_count = cur.fetchone()[0]
    
    # Calculate how many records to sample
    sample_size = min(max(1, round(total_count*sample_rate)), limit)
    
    # Use MySQL's RAND() function for sampling
    query = f"""
        SELECT * FROM {table_name}
        ORDER BY RAND()
        LIMIT {sample_size}
    """
    cur.execute(query)
    sample_data = cur.fetchall()
    cur.close()

    return sample_data, sample_size, total_count

def rds_detect_pii(sample_data, schema, region_name="eu-central-1"):
    try:
        # Create a Bedrock Runtime client
        client = boto3.client("bedrock-runtime", region_name=region_name)
    
        prompt = f"""Here is the sample data and schema of a specific database table.
    
        Sample Data:
        {sample_data}
        
        Table schema: 
        {schema}
    
        Detect PII categories in the provided data and schema above, and follow the instruction to return the result in JSON format.
        If the schema name is obviously a PII categories, such as user_id, please label no matter data exist or not.
        """
        
        messages = [
            {
                "role": "user",
                "content": [{ "text": prompt }],
            }
        ]
        system = [{ "text": SYSTEM_PROMPT }]
        inf_params = {"maxTokens": 4096, "topP": 0.1, "temperature": 0.3}
        
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

def process_single_table(cnx, db_name, table_name, 
                      region_name, db_identifier, db_type, sample_rate, limit, delay, debug, results):
    """
    Process a single table for PII detection
    """
    result = {}
    result['source_type'] = db_type.upper()  # 'RDS' or 'AURORA'
    result['region'] = region_name
    result['db_identifier'] = db_identifier
    result['db_name'] = db_name
    result['table_name'] = table_name
    
    try:
        # Get table schema and sample data
        schema = get_schema(cnx, db_name, table_name)
        sample_data, sample_size, total_count = get_sample_data(cnx, db_name, table_name, sample_rate, limit)

        if len(schema) > 0 and len(sample_data) > 0:
            result['sample_size'] = sample_size
            result['total_row'] = total_count
            result['schema'] = [col[0] for col in schema]
            if debug:
                column_names = [col[0] for col in schema]
                result['sample_record'] = str(dict(zip(column_names, sample_data[0])))
            
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
        else:
            # Handle case where table has no schema or data
            result['error'] = f"Table '{table_name}' has no schema or sample data available"
            result['timestamp'] = datetime.now().isoformat()
            print(f"Warning: Skipping table '{db_name}.{table_name}' - no schema or sample data available")
            results.append(result.copy())
            
    except mysql.connector.Error as e:
        # Handle MySQL-specific errors
        error_msg = f"MySQL error processing table '{db_name}.{table_name}': {e}"
        print(f"Error: {error_msg}")
        result['error'] = error_msg
        result['timestamp'] = datetime.now().isoformat()
        results.append(result.copy())
        
    except Exception as e:
        # Handle any other unexpected errors
        error_msg = f"Unexpected error processing table '{db_name}.{table_name}': {e}"
        print(f"Error: {error_msg}")
        result['error'] = error_msg
        result['timestamp'] = datetime.now().isoformat()
        results.append(result.copy())

def process_database(cnx, db_name, 
                   region_name, db_identifier, db_type, sample_rate, limit, delay, debug, results):
    """
    Process all tables in a database for PII detection
    """
    try:
        # Get list of tables in the database
        table_list = get_tables(cnx, db_name)
        print(f"Processing database '{db_name}' with {len(table_list)} tables...")
        
        for i, table in enumerate(table_list, 1):
            table_name = table[0]
            print(f"Processing table {i}/{len(table_list)}: {db_name}.{table_name}")
            
            try:
                process_single_table(cnx, db_name, table_name, 
                              region_name, db_identifier, db_type, sample_rate, limit, 
                              delay, debug, results)
            except Exception as e:
                # Log the error but continue with the next table
                print(f"Error processing table '{db_name}.{table_name}': {e}")
                print(f"Continuing with remaining tables in database '{db_name}'...")
                
            # Add delay between table processing
            if delay > 0 and i < len(table_list):  # Don't delay after the last table
                time.sleep(delay)
                
    except mysql.connector.Error as e:
        print(f"MySQL error accessing database '{db_name}': {e}")
        print(f"Skipping database '{db_name}' and continuing with remaining databases...")
        
    except Exception as e:
        print(f"Unexpected error processing database '{db_name}': {e}")
        print(f"Skipping database '{db_name}' and continuing with remaining databases...")

def main():
    parser = argparse.ArgumentParser(description='PII Detection for RDS/Aurora Databases')
    parser.add_argument('--db-type', choices=['rds', 'aurora'], required=True, help='Type of database: "rds" for RDS DB instance, "aurora" for Aurora DB cluster')
    parser.add_argument('--db-identifier', required=True, help='RDS DB instance identifier or Aurora DB cluster identifier')
    parser.add_argument('--port', type=int, default=3306, help='Database port (default: 3306)')
    
    # Authentication options - either secret name or direct credentials
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('--secret-name', help='AWS Secrets Manager secret name containing database credentials')
    auth_group.add_argument('--username', help='Database username (requires --password)')
    parser.add_argument('--password', help='Database password (requires --username)')
    
    parser.add_argument('--region-name', default='eu-central-1', help='AWS region name (default: eu-central-1)')
    parser.add_argument('--db-name', help='Specific database name to scan (optional)')
    parser.add_argument('--table-name', help='Specific table name to scan (requires --db-name)')
    parser.add_argument('--output', default='pii-detect-rds.jsonl', help='Output file path (default: pii-detect-rds.jsonl)')
    parser.add_argument('--sample-rate', type=float, default=0.2, help='Fraction of records to sample per table (default: 0.2)')
    parser.add_argument('--limit', type=int, default=10000, help='Maximum number of records to sample per table (default: 10000)')
    parser.add_argument('--delay', type=int, default=5, help='Delay between API calls in seconds (default: 5)')
    parser.add_argument('--debug', action='store_true', help='Include sample record in output (default: False)')
    parser.add_argument('-y', '--yes', action='store_true', help='Bypass confirmation prompt (default: False)')
    
    args = parser.parse_args()
    
    # Validate authentication arguments
    if args.username and not args.password:
        print("Error: --username requires --password")
        return
    if args.password and not args.username:
        print("Error: --password requires --username")
        return
    
    db_type = args.db_type
    db_identifier = args.db_identifier
    db_port = args.port
    secret_name = args.secret_name
    username = args.username
    password = args.password
    region_name = args.region_name
    db_name = args.db_name
    table_name = args.table_name
    output_file = args.output
    sample_rate = args.sample_rate
    limit = args.limit
    delay = args.delay
    debug = args.debug
    bypass_confirmation = args.yes
    
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
        else:
            # For RDS DB instances
            response = rds_client.describe_db_instances(DBInstanceIdentifier=db_identifier)
            db_endpoint = response['DBInstances'][0]['Endpoint']['Address']
    except ClientError as e:
        print(f"Error retrieving database information: {e}")
        return

    # Get database credentials - either from Secrets Manager or direct input
    if secret_name:
        secret = get_secret(secret_name, region_name)
        host = secret.get('host', db_endpoint)
        port = secret.get('port', db_port)
        username = secret.get('username')
        password = secret.get('password')
    else:
        # Use direct credentials
        host = db_endpoint
        port = db_port

    results = []
    cnx = None
    
    try:
        # Create MySQL connection
        cnx = mysql.connector.connect(
            host=host,
            port=port,
            user=username,
            password=password
        )
        
        # If db_name is provided, check if it exists
        if db_name:
            db_list = get_databases(cnx)
            db_names = [db[0] for db in db_list]
            if db_name not in db_names:
                print(f"\nError: Database '{db_name}' does not exist.")
                return
                
            # If table_name is provided, check if it exists
            if table_name:
                table_list = get_tables(cnx, db_name)
                table_names = [table[0] for table in table_list]
                if table_name not in table_names:
                    print(f"\nError: Table '{table_name}' does not exist in database '{db_name}'.")
                    return

        # Count databases and tables for summary
        if db_name and table_name:
            # Single table scan
            table_count = 1
            db_count = 1
        elif db_name:
            # All tables in specific database
            table_list = get_tables(cnx, db_name)
            table_count = len(table_list)
            db_count = 1
        else:
            # All tables in all databases
            db_list = get_databases(cnx)
            user_dbs = [db[0] for db in db_list if db not in [('information_schema',), ('mysql',), ('performance_schema',), ('sys',)]]
            db_count = len(user_dbs)
            table_count = 0
            for db in user_dbs:
                table_list = get_tables(cnx, db)
                table_count += len(table_list)

        # Prepare summary information for confirmation
        print("\nPII Detection Summary:")
        print(f"- DB Type: {db_type.upper()}")
        print(f"- DB Identifier: {db_identifier}")
        print(f"- DB Endpoint: {db_endpoint}")
        print(f"- DB Port: {port}")
        print(f"- Region: {region_name}")
        print(f"- Sample Rate: {sample_rate}")
        print(f"- Sample Limit: {limit} records per table")
        
        if db_name and table_name:
            print(f"- Target: Single table '{table_name}' in database '{db_name}'")
        elif db_name:
            print(f"- Target: All tables in database '{db_name}' ({table_count} tables)")
        else:
            print(f"- Target: All tables in all user databases ({db_count} databases, {table_count} tables)")
        
        # Ask for confirmation unless bypassed
        if not bypass_confirmation:
            confirm = input("\nDo you want to proceed with PII detection? (y/n): ").strip().lower()
            if confirm != 'y' and confirm != 'yes':
                print("PII detection cancelled.")
                return
            
        print("\nStarting PII detection...\n")

        # If specific db_name is provided
        if db_name:
            # If specific table_name is also provided
            if table_name:
                try:
                    process_single_table(cnx, db_name, table_name, 
                                        region_name, db_identifier, db_type, sample_rate, limit, 
                                        delay, debug, results)
                except Exception as e:
                    print(f"Error processing table '{db_name}.{table_name}': {e}")
            else:
                # Process all tables in the specified database
                try:
                    process_database(cnx, db_name, 
                                   region_name, db_identifier, db_type, sample_rate, limit, 
                                   delay, debug, results)
                except Exception as e:
                    print(f"Error processing database '{db_name}': {e}")
        else:
            # Get list of databases and process all
            try:
                db_list = get_databases(cnx)
                user_dbs = [db[0] for db in db_list if db not in [('information_schema',), ('mysql',), ('performance_schema',), ('sys',)]]
                
                print(f"Processing {len(user_dbs)} user databases...")
                for i, db_name in enumerate(user_dbs, 1):
                    print(f"\nProcessing database {i}/{len(user_dbs)}: {db_name}")
                    try:
                        process_database(cnx, db_name, 
                                       region_name, db_identifier, db_type, sample_rate, limit, 
                                       delay, debug, results)
                    except Exception as e:
                        print(f"Error processing database '{db_name}': {e}")
                        print(f"Continuing with remaining databases...")
                        
            except Exception as e:
                print(f"Error retrieving database list: {e}")
                print("Unable to continue with database processing.")

        # Save results to JSONL file
        save_list_to_jsonl(results, output_file)
        print(f"Results saved to {output_file}")
        
    except mysql.connector.Error as e:
        print(f"MySQL Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the connection gracefully
        if cnx and cnx.is_connected():
            cnx.close()
            print("Database connection closed.")

if __name__ == "__main__":
    main()
