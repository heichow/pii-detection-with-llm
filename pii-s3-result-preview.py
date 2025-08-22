#!/usr/bin/env python3

import json
import boto3
import argparse
from botocore.exceptions import ClientError

def generate_presigned_url(s3_client, bucket, key, expiration=3600):
    """Generate a presigned URL for an S3 object"""
    try:
        response = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket, 'Key': key},
            ExpiresIn=expiration
        )
        return response
    except ClientError:
        return None

def main():
    parser = argparse.ArgumentParser(description='Add presigned URLs to PII detection results')
    parser.add_argument('--input', default='pii-detect-s3.jsonl', help='Input JSONL file')
    parser.add_argument('--output', help='Output JSONL file (default: overwrites input)')
    parser.add_argument('--region', default='ap-southeast-1', help='AWS region')
    parser.add_argument('--expiration', type=int, default=3600, help='URL expiration in seconds')
    
    args = parser.parse_args()
    output_file = args.output or args.input
    
    s3_client = boto3.client('s3', region_name=args.region)
    
    updated_lines = []
    
    with open(args.input, 'r') as f:
        for line in f:
            data = json.loads(line.strip())
            
            if 'bucket' in data and 'object_key' in data:
                presigned_url = generate_presigned_url(
                    s3_client, 
                    data['bucket'], 
                    data['object_key'], 
                    args.expiration
                )
                if presigned_url:
                    data['presigned_url'] = presigned_url
            
            updated_lines.append(json.dumps(data))
    
    with open(output_file, 'w') as f:
        for line in updated_lines:
            f.write(line + '\n')
    
    print(f"Updated {len(updated_lines)} records with presigned URLs")
    print(f"Output written to: {output_file}")

if __name__ == "__main__":
    main()
