# CloudBull 🐂

CloudBull is a lightweight Python-based AWS security and misconfiguration scanner.

## Features
- Audits S3 bucket public access
- Detects overly permissive IAM policies
- Identifies exposed Security Groups
- Flags EC2 instances with public IPs
- Reviews ECS services for potential exposure

## Tech Stack
- Python
- AWS SDK (boto3)
- Tabulate for reporting

## Usage
```bash
pip install -r requirements.txt
python3 CloudBull.py
