# PII Detection with Amazon Bedrock

This repository contains tools for detecting Personally Identifiable Information (PII) in AWS resources using Amazon Bedrock's Nova Pro model. The tools can scan data in RDS/Aurora databases and S3 buckets to identify potential PII.

## Overview

The solution consists of two main scripts:

1. `pii-detect-rds.py`: Scans RDS instances and Aurora clusters for PII data
2. `pii-detect-s3.py`: Scans objects in S3 buckets for PII data

Both scripts use Amazon Bedrock's Nova Pro model to analyze data and identify PII categories based on a predefined list.

## Prerequisites

### AWS Account Requirements

- AWS account with access to the following services:
  - Amazon Bedrock
  - Amazon RDS/Aurora (for database scanning)
  - Amazon S3 (for S3 object scanning)
  - AWS Secrets Manager
  - Amazon VPC (for RDS/Aurora connectivity)

### IAM Permissions

The IAM user or role running these scripts needs the following permissions:

1. **Amazon Bedrock Permissions**:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:InvokeModel",
           "bedrock:InvokeModelWithResponseStream"
         ],
         "Resource": [
           "arn:aws:bedrock:*:*:inference-profile/*",
           "arn:aws:bedrock:*::foundation-model/*"
         ]
       }
     ]
   }
   ```

2. **RDS Permissions** (for `pii-detect-rds.py`):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "rds:DescribeDBClusters",
           "rds:DescribeDBInstances"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

3. **Secrets Manager Permissions** (for `pii-detect-rds.py`):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "secretsmanager:GetSecretValue"
         ],
         "Resource": "arn:aws:secretsmanager:*:*:secret:*"
       }
     ]
   }
   ```

4. **S3 Permissions** (for `pii-detect-s3.py`):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:ListBucket",
           "s3:GetObject"
         ],
         "Resource": [
           "arn:aws:s3:::your-bucket-name",
           "arn:aws:s3:::your-bucket-name/*"
         ]
       }
     ]
   }
   ```

5. **STS Permissions** (for `pii-detect-s3.py`):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "sts:GetCallerIdentity"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

### Amazon Bedrock Model Access

You need to request access to the Amazon Nova Pro model in your AWS account:

1. Navigate to the Amazon Bedrock console
2. Go to "Model access" in the left navigation
3. Request access to "Amazon Nova Pro" model
4. Wait for approval (usually immediate)

### Network Connectivity for RDS/Aurora

To scan RDS/Aurora databases:

1. Ensure the machine running the script has network connectivity to the RDS instance or Aurora cluster endpoint
2. If the database is in a VPC:
   - Run the script from an EC2 instance in the same VPC, or
   - Set up VPC peering, a VPN connection, or AWS Direct Connect
   - Configure security groups to allow MySQL/PostgreSQL traffic (port 3306/5432) from the machine running the script

### Secrets Manager Setup for RDS/Aurora

For RDS/Aurora scanning, create a secret in AWS Secrets Manager with database credentials:

1. Navigate to AWS Secrets Manager console
2. Click "Store a new secret"
3. Select "Credentials for RDS database"
4. Enter the database username and password
5. Select the RDS database (optional)
6. Name the secret (e.g., "my-rds-credentials")
7. Complete the creation process

The secret should have this format:
```json
{
  "username": "your-db-username",
  "password": "your-db-password"
}
```

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/pii-detection-with-llm.git
   cd pii-detection-with-llm
   ```

2. Install required Python packages:
   ```bash
   pip install boto3 mysql-connector-python
   ```

## Usage

### Scanning RDS/Aurora Databases

```bash
python pii-detect-rds.py --db-type <rds|aurora> --db-identifier <db-identifier> [authentication-options] [options]
```

#### Required Parameters:
- `--db-type`: Type of database: "rds" for RDS DB instance, "aurora" for Aurora DB cluster
- `--db-identifier`: RDS DB instance identifier or Aurora DB cluster identifier

#### Authentication Options (choose one):
- `--secret-name`: AWS Secrets Manager secret name containing database credentials
- `--username` and `--password`: Direct database credentials

#### Optional Parameters:
- `--port`: Database port (default: 3306)
- `--region-name`: AWS region name (default: ap-southeast-1)
- `--db-name`: Specific database name to scan (optional)
- `--table-name`: Specific table name to scan (requires --db-name)
- `--output`: Output file path (default: pii-detect-rds.jsonl)
- `--sample-rate`: Fraction of records to sample per table (default: 0.2)
- `--limit`: Maximum number of records to sample per table (default: 10000)
- `--delay`: Delay between API calls in seconds (default: 5)

#### Examples:

Scan all databases in an Aurora cluster:
```bash
python pii-detect-rds.py --db-type aurora --db-identifier my-aurora-cluster --secret-name my-db-credentials --region-name us-west-2
```

Scan all databases in an RDS instance:
```bash
python pii-detect-rds.py --db-type rds --db-identifier my-rds-instance --secret-name my-db-credentials --region-name us-west-2
```

Scan a specific database:
```bash
python pii-detect-rds.py --db-type rds --db-identifier my-rds-instance --secret-name my-db-credentials --db-name my_database
```

Scan a specific table:
```bash
python pii-detect-rds.py --db-type aurora --db-identifier my-aurora-cluster --secret-name my-db-credentials --db-name my_database --table-name users
```

Using direct credentials:
```bash
python pii-detect-rds.py --db-type rds --db-identifier my-rds-instance --username myuser --password mypass --region-name us-west-2
```

### Scanning S3 Objects

```bash
python pii-detect-s3.py --bucket-name <bucket-name> [options]
```

#### Required Parameters:
- `--bucket-name`: S3 bucket name

#### Optional Parameters:
- `--region-name`: AWS region name (default: ap-southeast-1)
- `--prefix`: S3 prefix to filter objects (default: empty string)
- `--sample-rate`: Fraction of objects to sample per folder (default: 0.2)
- `--limit`: Maximum number of samples per folder (default: 100000)
- `--output`: Output file path (default: pii-detect-s3.jsonl)
- `--delay`: Delay between API calls in seconds (default: 5)

#### Examples:

Scan all objects in a bucket:
```bash
python pii-detect-s3.py --bucket-name my-data-bucket --region-name us-west-2
```

Scan objects with a specific prefix:
```bash
python pii-detect-s3.py --bucket-name my-data-bucket --prefix customer-data/
```

Adjust sampling rate:
```bash
python pii-detect-s3.py --bucket-name my-data-bucket --sample-rate 0.1 --limit 50
```

## Output Format

Both scripts generate output in JSONL format (one JSON object per line). Each line contains:

- Source information (database/table or S3 bucket/object)
- Sample size and total count
- PII detection results
- Token usage information
- Timestamp

Example output for RDS/Aurora scanning:
```json
{
  "source_type": "RDS",
  "region": "us-west-2",
  "db_identifier": "my-rds-instance",
  "db_name": "my_database",
  "table_name": "users",
  "sample_size": 100,
  "total_row": 5000,
  "has_pii": true,
  "pii_categories": ["NAME", "EMAIL", "PHONE_NUMBER"],
  "pii_schema_mapping": {
    "NAME": "full_name",
    "EMAIL": "email_address",
    "PHONE_NUMBER": "contact_number"
  },
  "input_token": 1245,
  "output_token": 87,
  "timestamp": "2025-06-12T04:00:00.000000"
}
```

Example output for S3 scanning:
```json
{
  "source_type": "S3",
  "region": "us-west-2",
  "bucket": "my-data-bucket",
  "folder": "customer-data/",
  "sample_size": 10,
  "total_objects": 100,
  "object_key": "customer-data/report.pdf",
  "file_type": "pdf",
  "file_size": 1024000,
  "has_pii": true,
  "pii_categories": ["NAME", "ADDRESS", "CREDIT_CARD_NUMBER"],
  "input_token": 2456,
  "output_token": 92,
  "timestamp": "2025-06-12T04:00:00.000000"
}
```

For image files, the output includes bounding box coordinates for each detected PII element:
```json
{
  "source_type": "S3",
  "region": "us-west-2",
  "bucket": "my-data-bucket",
  "folder": "customer-data/",
  "sample_size": 10,
  "total_objects": 100,
  "object_key": "customer-data/passport.png",
  "file_type": "png",
  "file_size": 512000,
  "has_pii": true,
  "pii_categories": ["NAME", "DATE_OF_BIRTH", "NATIONAL_IDENTIFICATION_NUMBER", "PROFILE_PHOTO"],
  "pii_bounding_box": {
    "NAME": [391, 182, 647, 809],
    "DATE_OF_BIRTH": [65, 204, 280, 449],
    "NATIONAL_IDENTIFICATION_NUMBER": [120, 350, 480, 410],
    "PROFILE_PHOTO": [50, 50, 250, 250]
  },
  "input_token": 1856,
  "output_token": 105,
  "timestamp": "2025-06-12T04:00:00.000000"
}
```

## Limitations

- The scripts use sampling to analyze data, so they may not detect all PII in very large datasets
- Supported file types for S3 scanning: png, jpeg, gif, webp, pdf, csv, doc, docx, xls, xlsx, html, txt, md
- The accuracy of PII detection depends on the capabilities of the Amazon Bedrock Nova Pro model
- Token limits may affect the analysis of very large files or database records

## Security Considerations

- The scripts do not extract or store the actual PII data, only the categories detected
- Database credentials are stored securely in AWS Secrets Manager
- Consider running these scripts in a secure environment with appropriate access controls
- Review the output files for sensitive information before sharing

## License

[Include your license information here]
