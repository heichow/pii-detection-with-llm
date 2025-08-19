#!/usr/bin/env python3
"""
PII Detection for S3 Objects

This script scans S3 objects for PII data using Amazon Bedrock.
"""

import boto3
import json
import random
import time
import argparse
from collections import defaultdict
from datetime import datetime
from botocore.exceptions import ClientError
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

def sample_s3_data_by_folder(bucket_name, prefix='', sample_rate=0.1, limit=100):
    """
    Sample S3 objects at a specified rate per folder, including the root folder.

    Args:
        bucket_name (str): The S3 bucket name
        prefix (str): Optional prefix to filter objects (like a directory path)
        sample_rate (float): Fraction of objects to sample per folder (0.0 to 1.0)
        limit (int): Optional maximum number of samples per folder

    Returns:
        dict: Dictionary with folders as keys and lists of sampled objects as values
    """
    s3_client = boto3.client('s3')

    # Get all objects with the given prefix
    paginator = s3_client.get_paginator('list_objects_v2')

    # Group objects by folder
    folders = defaultdict(list)
    root_objects = []

    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
        if 'Contents' not in page:
            continue

        for obj in page['Contents']:
            key = obj['Key']
            
            # Skip folder-only objects (keys ending with /)
            if key.endswith('/'):
                continue

            # Check if the object is in the root (no slashes except possibly at the end)
            if '/' not in key or (key.count('/') == 1 and key.endswith('/')):
                root_objects.append(obj)
            else:
                # Extract folder path (everything before the last slash)
                folder = '/'.join(key.split('/')[:-1]) + '/'
                folders[folder].append(obj)

    # Add root objects to the folders dictionary
    if root_objects:
        folders['/'] = root_objects
    
    # Sample objects from each folder
    sample_data = {}

    for folder, objects in folders.items():
        # Calculate number of objects to sample
        sample_size = min(max(1, int(len(objects) * sample_rate)), limit)

        # Randomly sample objects
        if sample_size < len(objects):
            sample_objects = random.sample(objects, sample_size)
        else:
            sample_objects = objects
        
        # Store metadata along with sampled objects
        sample_data[folder] = {
            'total_objects': len(objects),
            'sample_size': len(sample_objects),
            'sampled_objects': sample_objects
        }

    return sample_data

def s3_detect_pii(s3_path, region_name="ap-southeast-1"):
    """
    Detect PII in S3 objects using Amazon Bedrock.
    
    Args:
        s3_path (str): S3 URI path to the object
        region_name (str): AWS region name
        
    Returns:
        dict or str: Bedrock response or error message
    """
    # Create a Bedrock Runtime client
    client = boto3.client("bedrock-runtime", region_name=region_name)

    model_id = get_nova_model_id(region_name)
    content = []
    
    file_support = False
    ext = s3_path.split('.')[-1]
    if ext=='jpg':
        ext = 'jpeg'
    if ext in ['png', 'jpeg', 'gif', 'webp']:
        file_support = True
        content.append({
            "image": {
                "format": ext,
                "source": {
                    "s3Location": { 
                        "uri": s3_path
                    }
                },
            }
        })
    if ext in ['pdf', 'csv', 'doc', 'docx', 'xls', 'xlsx', 'html', 'txt', 'md']:
        file_support = True
        content.append({
            "document": {
                "format": ext,
                "name": "sample_doc",
                "source": {
                    "s3Location": {
                        "uri": s3_path
                    }
                },
            }
        })
    
    content.append({"text": "Detect PII categories in the provided data, and follow the instruction to return the result in JSON format."})
    
    messages = [
        {
            "role": "user",
            "content": content,
        }
    ]
    system = [{ "text": SYSTEM_PROMPT }]
    inf_params = {"maxTokens": 1024, "topP": 0.1, "temperature": 0.3}
    
    if file_support:
        try:
            response = client.converse(
                modelId=model_id, messages=messages, system=system, inferenceConfig=inf_params
            )
            return response     
              
        except (ClientError, Exception) as e:
            error_msg = f"ERROR: Can't invoke '{model_id}'. Reason: {e}"
            print(error_msg)
            return error_msg
    else:
        error_msg = f"ERROR: Can't invoke '{model_id}'. Reason: File type {ext} is not supported."
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

def main():
    parser = argparse.ArgumentParser(description='PII Detection for S3 Objects')
    parser.add_argument('--bucket-name', required=True, help='S3 bucket name')
    parser.add_argument('--region-name', default='ap-southeast-1', help='AWS region name (default: ap-southeast-1)')
    parser.add_argument('--prefix', default='', help='S3 prefix to filter objects (default: empty string)')
    parser.add_argument('--sample-rate', type=float, default=0.2, help='Fraction of objects to sample per folder (default: 0.2)')
    parser.add_argument('--limit', type=int, default=100000, help='Maximum number of samples per folder (default: 100)')
    parser.add_argument('--output', default='pii-detect-s3.jsonl', help='Output file path (default: pii-detect-s3.jsonl)')
    parser.add_argument('--delay', type=int, default=5, help='Delay between API calls in seconds (default: 5)')
    
    args = parser.parse_args()
    
    bucket_name = args.bucket_name
    region_name = args.region_name
    prefix = args.prefix
    sample_rate = args.sample_rate
    limit = args.limit
    output_file = args.output
    delay = args.delay

    results = []
    sample_data = sample_s3_data_by_folder(bucket_name, prefix, sample_rate, limit)
    
    # Calculate total objects to be processed
    total_folders = len(sample_data.keys())
    total_samples = sum(folder['sample_size'] for folder in sample_data.values())
    
    print(f"\nSummary of objects to be processed:")
    print(f"- Total folders: {total_folders}")
    print(f"- Total objects to scan: {total_samples}")
    print(f"- Sample rate: {sample_rate}")
    print(f"- Region: {region_name}")
    print(f"- Bucket: {bucket_name}")
    print(f"- Prefix: {prefix or '(root)'}")
    
    # Ask for confirmation
    confirm = input("\nDo you want to proceed with PII detection? (y/n): ").strip().lower()
    if confirm != 'y' and confirm != 'yes':
        print("PII detection cancelled.")
        return
    
    print("\nStarting PII detection...\n")
    
    for folder_name in sample_data.keys():
        folder = sample_data[folder_name]

        result = {}
        result['source_type'] = 'S3'
        result['region'] = region_name
        result['bucket'] = bucket_name
        result['folder'] = folder_name
        result['sample_size'] = folder['sample_size']
        result['total_objects'] = folder['total_objects']

        for sample_object in folder['sampled_objects']:
            object_key = sample_object['Key']
            print(object_key)
            ext = object_key.split('.')[-1]
            result['object_key'] = object_key
            result['file_type'] = ext
            result['file_size'] = sample_object['Size']
            
            s3_path = f"s3://{bucket_name}/{object_key}" 
            model_response = s3_detect_pii(s3_path, region_name)
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
            time.sleep(delay)

    # Save results to JSONL file
    save_list_to_jsonl(results, output_file)
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
