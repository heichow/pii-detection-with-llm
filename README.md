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
   pip install boto3 mysql-connector-python numpy==2.2.1 pandas Pillow 
   ```

3. Set up rule-based detection files (optional but recommended):

   Create `rule-based-attribute-mapping.csv` for field name matching:
   ```csv
   pii_category,attribute_name
   USER_ID,user_id
   EMAIL,email
   PHONE_NUMBER,phone
   NAME,name
   ```

   Create `rule-based-regex-mapping.tsv` for data pattern matching:
   ```tsv
   pii_category	regex
   EMAIL	^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
   PHONE	^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$
   SSN	^\d{3}-?\d{2}-?\d{4}$
   ```

   **Note**: The TSV file uses tab characters (`\t`) as separators, not spaces.

## Usage

### Scanning RDS/Aurora Databases

The RDS/Aurora scanner uses three complementary detection methods for comprehensive PII identification:

1. **AI-powered detection**: Amazon Bedrock Nova Pro analyzes sample data and schema
2. **Attribute-based rule detection**: Matches database field names to known PII patterns
3. **Regex-based rule detection**: Analyzes actual data values using regex patterns

#### Rule-Based PII Detection

##### Attribute-Based Detection

Create a CSV file named `rule-based-attribute-mapping.csv` to define explicit field name mappings:

```csv
pii_category,attribute_name
USER_ID,user_id
DRIVER_ID,driver_id
EMAIL,customer_email
PHONE_NUMBER,phone
NAME,full_name
```

The scanner supports both exact matching and substring matching. For example, if your CSV contains `email` and your database has a field named `customer_email`, it will be detected as a substring match.

##### Regex-Based Detection

Create a TSV file named `rule-based-regex-mapping.tsv` to define regex patterns for detecting PII in actual data values:

```tsv
pii_category	regex
EMAIL	^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
PHONE	^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$
SSN	^\d{3}-?\d{2}-?\d{4}$
CREDIT_CARD	^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$
```

**Note**: Use TSV (tab-separated) format for regex patterns since they often contain commas that would break CSV parsing.

The scanner will automatically load both files and apply all detection methods to provide comprehensive PII identification with confidence scores and detailed reasoning.

#### Usage

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
- `--debug`: Include sample record in output (default: False)
- `-y`, `--yes`: Bypass confirmation prompt (default: False)

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
- `--debug`: Include presigned URL in output (default: False)
- `-y`, `--yes`: Bypass confirmation prompt (default: False)

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

### Visualizing PII Bounding Boxes

Use `pii-bounding-boxes.py` to visualize PII detection results on images:

```bash
python pii-bounding-boxes.py [--s3-pii-result <jsonl-file>] [--output-dir <output-directory>]
```

#### Optional Parameters:
- `--s3-pii-result`: Path to JSONL file containing PII detection results (default: pii-detect-s3.jsonl)
- `--output-dir`: Directory to save images with bounding boxes (default: current directory)

#### Example:
```bash
python pii-bounding-boxes.py --s3-pii-result pii-detect-s3.jsonl --output-dir ./output-images
```

This script processes the JSONL output from S3 scanning and creates new images with bounding boxes drawn around detected PII elements.

## Output Format

Both scripts generate output in JSONL format (one JSON object per line). The output format has been enhanced to include confidence scores and detailed reasoning for each detected PII category.

### Enhanced PII Detection Results

Each detection result now includes:

- **Source information**: Database/table or S3 bucket/object details
- **Sample size and total count**: Statistics about data analyzed
- **Enhanced PII detection results**: Categories with confidence scores and reasoning
- **Schema mapping**: Which database fields contain which PII types
- **Token usage information**: Bedrock API usage metrics
- **Timestamp**: When the analysis was performed

### RDS/Aurora Output Format

Example output for RDS/Aurora scanning with the new enhanced format:

```json
{
  "source_type": "RDS",
  "region": "us-west-2",
  "db_identifier": "my-rds-instance",
  "db_name": "my_database",
  "table_name": "users",
  "sample_size": 100,
  "total_row": 5000,
  "schema": ["user_id", "full_name", "email_address", "phone_number"],
  "has_pii": true,
  "pii_categories": {
    "NAME": {
      "confidence_score": 1.0,
      "reason": "Rule-based detection: schema field 'full_name' exact match with PII field 'name'; AI-based detection found names in sample data"
    },
    "EMAIL": {
      "confidence_score": 0.9,
      "reason": "Regex-based detection: field 'email_address' matches pattern for EMAIL; AI-based detection confirmed email addresses"
    },
    "PHONE_NUMBER": {
      "confidence_score": 0.8,
      "reason": "Rule-based detection: schema field 'phone_number' substring match with PII field 'phone'"
    },
    "USER_ID": {
      "confidence_score": 1.0,
      "reason": "Rule-based detection: schema field 'user_id' exact match with PII field 'user_id'"
    }
  },
  "pii_schema_mapping": {
    "NAME": ["full_name"],
    "EMAIL": ["email_address"],
    "PHONE_NUMBER": ["phone_number"],
    "USER_ID": ["user_id"]
  },
  "input_token": 1245,
  "output_token": 87,
  "timestamp": "2025-06-12T04:00:00.000000"
}
```

### Detection Method Reasoning

The `reason` field provides transparency about how each PII category was detected:

- **Rule-based detection**: Field name matching (exact or substring)
- **Regex-based detection**: Data value pattern matching
- **AI-based detection**: Amazon Bedrock Nova Pro model analysis

### S3 Output Format

Example output for S3 scanning (format remains similar for S3 objects):

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
  "pii_categories": {
    "NAME": {
      "confidence_score": 0.95,
      "reason": "AI-based detection found personal names in document content"
    },
    "ADDRESS": {
      "confidence_score": 0.87,
      "reason": "AI-based detection identified address information"
    },
    "CREDIT_CARD_NUMBER": {
      "confidence_score": 0.92,
      "reason": "AI-based detection found credit card number patterns"
    }
  },
  "input_token": 2456,
  "output_token": 92,
  "timestamp": "2025-06-12T04:00:00.000000"
}
```

### Image Files with Bounding Boxes

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
  "pii_categories": {
    "NAME": {
      "confidence_score": 0.98,
      "reason": "AI-based detection found name text in image"
    },
    "DATE_OF_BIRTH": {
      "confidence_score": 0.94,
      "reason": "AI-based detection identified date of birth"
    },
    "NATIONAL_IDENTIFICATION_NUMBER": {
      "confidence_score": 0.96,
      "reason": "AI-based detection found ID number pattern"
    },
    "PROFILE_PHOTO": {
      "confidence_score": 0.99,
      "reason": "AI-based detection identified facial features"
    }
  },
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
- Supported file types for S3 scanning: png, jpeg, gif, webp, pdf, csv, doc, docx, xls, xlsx, html, txt, md, json, jsonl
- The accuracy of AI-based PII detection depends on the capabilities of the Amazon Bedrock Nova Pro model
- Rule-based detection accuracy depends on the completeness of your attribute and regex mapping files
- Regex patterns may have false positives or negatives depending on data format variations
- Token limits may affect the analysis of very large files or database records
- For RDS/Aurora scanning, regex-based detection is only applied to sampled data, not the entire dataset

## Security Considerations

- The scripts do not extract or store the actual PII data, only the categories detected
- Database credentials are stored securely in AWS Secrets Manager
- Consider running these scripts in a secure environment with appropriate access controls
- Review the output files for sensitive information before sharing

## License

[Include your license information here]
