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
import csv
import re
from botocore.exceptions import ClientError
from datetime import datetime
from prompt import SYSTEM_PROMPT

NOVA_PRO_MODEL_ID = "amazon.nova-pro-v1:0"

# Global variables for PII mappings
PII_ATTRIBUTE_MAPPINGS = {}
PII_REGEX_MAPPINGS = {}

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

def load_pii_attribute_mappings(csv_file="rule-based-attribute-mapping.csv"):
    """
    Load PII attribute mappings from CSV file for rule-based detection
    CSV format: pii_category, attribute_name
    Returns dict mapping attribute_name to pii_category
    """
    mappings = {}
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            # Strip whitespace from column names
            reader.fieldnames = [name.strip() if name else name for name in reader.fieldnames]
            
            for row in reader:
                # Create a new row dict with stripped keys
                clean_row = {k.strip(): v.strip() if v else v for k, v in row.items()}
                
                if 'pii_category' not in clean_row or 'attribute_name' not in clean_row:
                    print(f"Error: {csv_file} must have 'pii_category' and 'attribute_name' columns")
                    print(f"Debug: Available columns: {list(clean_row.keys())}")
                    return {}
                if clean_row['attribute_name'] and clean_row['pii_category']:
                    mappings[clean_row['attribute_name'].lower()] = clean_row['pii_category']
    except FileNotFoundError:
        print(f"Warning: {csv_file} not found. Rule-based PII detection disabled.")
    except Exception as e:
        print(f"Error loading {csv_file}: {e}")
    return mappings

def load_pii_regex_mappings(tsv_file="rule-based-regex-mapping.tsv"):
    """
    Load PII regex mappings from TSV file for rule-based detection
    TSV format: pii_category	regex (tab-separated)
    Returns dict mapping pii_category to compiled regex pattern
    """
    mappings = {}
    try:
        with open(tsv_file, 'r', encoding='utf-8') as f:
            # Read the first line to get headers
            first_line = f.readline().strip()
            if not first_line:
                print(f"Error: {tsv_file} is empty")
                return {}
            
            # Parse headers manually (tab-separated)
            headers = [h.strip() for h in first_line.split('\t')]
            
            # Check if we have the required columns
            if 'pii_category' not in headers or 'regex' not in headers:
                print(f"Error: {tsv_file} must have 'pii_category' and 'regex' columns")
                print(f"Found columns: {headers}")
                return {}
            
            # Get column indices
            pii_category_idx = headers.index('pii_category')
            regex_idx = headers.index('regex')
            
            # Read remaining lines
            for line_num, line in enumerate(f, start=2):
                line = line.strip()
                if not line:  # Skip empty lines
                    continue
                
                # Split the line by tab
                values = [v.strip() for v in line.split('\t')]
                
                # Make sure we have enough values
                if len(values) <= max(pii_category_idx, regex_idx):
                    print(f"Warning: Line {line_num} in {tsv_file} has insufficient columns, skipping")
                    continue
                
                pii_category = values[pii_category_idx]
                regex_pattern = values[regex_idx]
                
                # Skip if either value is empty
                if not pii_category or not regex_pattern:
                    print(f"Warning: Line {line_num} in {tsv_file} has empty values, skipping")
                    continue
                
                try:
                    # Compile the regex pattern
                    compiled_pattern = re.compile(regex_pattern)
                    mappings[pii_category] = compiled_pattern
                    print(f"Loaded regex pattern for {pii_category}: {regex_pattern}")
                except re.error as e:
                    print(f"Warning: Invalid regex pattern on line {line_num} for {pii_category}: {e}")
                    continue
                    
    except FileNotFoundError:
        print(f"Warning: {tsv_file} not found. Regex-based PII detection disabled.")
    except Exception as e:
        print(f"Error loading {tsv_file}: {e}")
        import traceback
        traceback.print_exc()
    
    return mappings

def apply_rule_based_pii(pii_result, schema, sample_data=None):
    """
    Apply rule-based PII detection by matching schema fields to CSV mappings and regex patterns
    Updated to work with new PII result format where pii_categories is a dict with confidence scores
    Supports:
    1. Exact matching and substring matching (if schema field contains the PII field name)
    2. Regex pattern matching against sample data
    Uses global PII_ATTRIBUTE_MAPPINGS and PII_REGEX_MAPPINGS variables
    """
    global PII_ATTRIBUTE_MAPPINGS, PII_REGEX_MAPPINGS
    if (not PII_ATTRIBUTE_MAPPINGS and not PII_REGEX_MAPPINGS) or not schema:
        return pii_result
    
    schema_fields = [col[0].lower() for col in schema]
    
    # Rule-based PII detection on schema field name
    for field in schema_fields:
        matched_categories = []
        
        # Check for exact match first
        if field in PII_ATTRIBUTE_MAPPINGS:
            matched_categories.append((PII_ATTRIBUTE_MAPPINGS[field], field, "exact match"))
        
        # Check for substring matches (if schema field contains any PII field name)
        for pii_field_name, pii_category in PII_ATTRIBUTE_MAPPINGS.items():
            if pii_field_name != field and pii_field_name in field:
                matched_categories.append((pii_category, pii_field_name, "substring match"))
        
        # Process all matched categories for this field
        for pii_category, matched_field, match_type in matched_categories:
            # Initialize pii_categories as dict if not present
            if 'pii_categories' not in pii_result:
                pii_result['pii_categories'] = {}
            
            # Determine confidence score based on match type
            confidence_score = 1.0 if match_type == "exact match" else 0.8
            reason = f"Rule-based detection: schema field '{field}' {match_type} with PII field '{matched_field}'"
            
            # Add to pii_categories with rule-based confidence and reason
            pii_result['pii_categories'][pii_category] = {
                "confidence_score": confidence_score,
                "reason": reason
            }
            
            # Add to pii_schema_mapping
            if 'pii_schema_mapping' not in pii_result:
                pii_result['pii_schema_mapping'] = {}
            if pii_category not in pii_result['pii_schema_mapping']:
                pii_result['pii_schema_mapping'][pii_category] = []
            if field not in pii_result['pii_schema_mapping'][pii_category]:
                pii_result['pii_schema_mapping'][pii_category].append(field)
            
            # Set has_pii to true if PII found
            pii_result['has_pii'] = True
    
    # Regex-based PII detection on sample data
    if sample_data and PII_REGEX_MAPPINGS:
        # Convert sample data to string format for regex matching
        if isinstance(sample_data, (list, tuple)) and len(sample_data) > 0:
            # sample_data is a list of tuples (rows), convert to list of strings
            for row_idx, row in enumerate(sample_data):
                for col_idx, value in enumerate(row):
                    if value is not None:
                        value_str = str(value)
                        field_name = schema_fields[col_idx] if col_idx < len(schema_fields) else f"column_{col_idx}"
                        
                        # Test each regex pattern against the value
                        for pii_category, regex_pattern in PII_REGEX_MAPPINGS.items():
                            if regex_pattern.search(value_str):
                                # Initialize pii_categories as dict if not present
                                if 'pii_categories' not in pii_result:
                                    pii_result['pii_categories'] = {}
                                
                                # Add to pii_categories with regex-based confidence and reason
                                pii_result['pii_categories'][pii_category] = {
                                    "confidence_score": 1.0,  # High confidence for regex matches
                                    "reason": f"Regex-based detection: field '{field_name}' matches pattern for {pii_category}"
                                }
                                 
                                # Add to pii_schema_mapping
                                if 'pii_schema_mapping' not in pii_result:
                                    pii_result['pii_schema_mapping'] = {}
                                if pii_category not in pii_result['pii_schema_mapping']:
                                    pii_result['pii_schema_mapping'][pii_category] = []
                                if field_name not in pii_result['pii_schema_mapping'][pii_category]:
                                    pii_result['pii_schema_mapping'][pii_category].append(field_name)
                                
                                # Set has_pii to true if PII found
                                pii_result['has_pii'] = True
    
    return pii_result

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
        """
        
        messages = [
            {
                "role": "user",
                "content": [{ "text": prompt }],
            }
        ]
        system = [{ "text": SYSTEM_PROMPT }]
        inf_params = {"maxTokens": 8192, "topP": 0.1, "temperature": 0.0}
        
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

        result['schema'] = [col[0] for col in schema]
        result['sample_size'] = sample_size
        result['total_row'] = total_count

        if len(sample_data) > 0:
            if debug:
                column_names = [col[0] for col in schema]
                result['sample_record'] = []
                for idx, data in enumerate(sample_data):
                    result['sample_record'].append(str(dict(zip(column_names, sample_data[idx]))))
            
            # Detect PII in the sample data
            model_response = rds_detect_pii(str(sample_data), str(schema), region_name)
            if isinstance(model_response, dict):
                pii_result = json.loads(model_response['output']['message']['content'][0]['text'])
                
                # Apply rule-based PII detection
                pii_result = apply_rule_based_pii(pii_result, schema, sample_data)
                
                result.update(pii_result)
                result['has_pii'] = len(pii_result['pii_categories']) > 0
                result['confidence_score'] = sum(cat['confidence_score'] for cat in pii_result['pii_categories'].values()) / len(pii_result['pii_categories'])
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
            result['error'] = f"Table '{table_name}' has no sample data available"
            result['timestamp'] = datetime.now().isoformat()
            print(f"Warning: Skipping table '{db_name}.{table_name}' - no sample data available")
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
    parser.add_argument('--delay', type=int, default=0, help='Delay between API calls in seconds (default: 0)')
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
    
    # Load PII mappings from CSV and TSV files into global variables
    global PII_ATTRIBUTE_MAPPINGS, PII_REGEX_MAPPINGS
    PII_ATTRIBUTE_MAPPINGS = load_pii_attribute_mappings()
    PII_REGEX_MAPPINGS = load_pii_regex_mappings("rule-based-regex-mapping.tsv")
    
    if PII_ATTRIBUTE_MAPPINGS:
        print(f"Loaded {len(PII_ATTRIBUTE_MAPPINGS)} PII attribute mappings from CSV")
    if PII_REGEX_MAPPINGS:
        print(f"Loaded {len(PII_REGEX_MAPPINGS)} PII regex patterns from TSV")
    
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
