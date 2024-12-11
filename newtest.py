#!/usr/bin/python3 -u
#
# Get the list of services accessed in a particular time period and compare with approved services
#
import sys
import boto3
import time
import datetime
import argparse
from dateutil.relativedelta import relativedelta

# List of approved services
approved_services = [
    "ACM", "ACMPCA", "AccessAnalyzer", "ApiGateway", "ApiGatewayV2", 
    "AppConfig", "AppStream", "Athena", "AuditManager", "AutoScaling", 
    "Backup", "Batch", "Cassandra", "CloudFormation", "CloudFront", 
    "CloudTrail", "CloudWatch", "Cloud9", "CodeDeploy", "Config", 
    "DynamoDB", "EC2", "ECR", "ECS", "EFS", "ElasticLoadBalancingV2", 
    "EventSchemas", "Events", "Glue", "GuardDuty", "IAM", "InspectorV2", 
    "KMS", "Kinesis", "KinesisAnalyticsV2", "KinesisFirehose", "Lambda", 
    "MSK", "NetworkFirewall", "NetworkManager", "OpenSearch", "QuickSight", 
    "RDS", "Redshift", "Route53", "Route53Resolver", "S3", "SES", "SNS", 
    "SQS", "SSM", "SecretsManager", "ServiceDiscovery", "StepFunctions", 
    "WAFv2", "Organizations", "ResourceGroups", "Support", "TransferFamily",
    "FSx", "CloudShell"
]

# Mapping of eventSource prefixes to service names
service_prefixes = {
    "acm": "ACM",
    "acm-pca": "ACMPCA",
    "access-analyzer": "AccessAnalyzer",
    "apigateway": "ApiGateway",
    "execute-api": "ApiGateway",
    "appconfig": "AppConfig",
    "appstream2": "AppStream",
    "athena": "Athena",
    "auditmanager": "AuditManager",
    "autoscaling": "AutoScaling",
    "backup": "Backup",
    "batch": "Batch",
    "cassandra": "Cassandra",
    "cloudformation": "CloudFormation",
    "cloudfront": "CloudFront",
    "cloudtrail": "CloudTrail",
    "cloudwatch": "CloudWatch",
    "monitoring": "CloudWatch",
    "logs": "CloudWatch",
    "cloud9": "Cloud9",
    "codedeploy": "CodeDeploy",
    "config": "Config",
    "dynamodb": "DynamoDB",
    "ec2": "EC2",
    "elasticloadbalancing": "EC2",
    "ecr": "ECR",
    "ecs": "ECS",
    "elasticfilesystem": "EFS",
    "efs": "EFS",
    "schemas": "EventSchemas",
    "events": "Events",
    "glue": "Glue",
    "guardduty": "GuardDuty",
    "iam": "IAM",
    "sts": "IAM",
    "signin": "IAM",
    "rolesanywhere": "IAM",
    "inspector2": "InspectorV2",
    "kms": "KMS",
    "kinesis": "Kinesis",
    "kinesisanalytics": "KinesisAnalyticsV2",
    "analytics": "KinesisAnalyticsV2",
    "firehose": "KinesisFirehose",
    "lambda": "Lambda",
    "kafka": "MSK",
    "network-firewall": "NetworkFirewall",
    "networkmanager": "NetworkManager",
    "es": "OpenSearch",
    "aoss": "OpenSearch",
    "quicksight": "QuickSight",
    "rds": "RDS",
    "redshift": "Redshift",
    "route53": "Route53",
    "route53resolver": "Route53Resolver",
    "s3": "S3",
    "ses": "SES",
    "sns": "SNS",
    "sqs": "SQS",
    "ssm": "SSM",
    "secretsmanager": "SecretsManager",
    "servicediscovery": "ServiceDiscovery",
    "states": "StepFunctions",
    "wafv2": "WAFv2",
    "waf-regional": "WAFv2",
    "organizations": "Organizations",
    "resource-groups": "ResourceGroups",
    "support": "Support",
    "transfer": "TransferFamily",
    "fsx": "FSx",
    "cloudshell": "CloudShell",
    "q": "Q"
}

def normalize_eventSource(eventSource):
    """Convert eventSource to service name using prefix mapping"""
    # Remove .amazonaws.com and convert to lowercase for comparison
    service = eventSource.replace(".amazonaws.com", "").lower()
    
    # Check if we have a direct mapping
    if service in service_prefixes:
        return service_prefixes[service]
        
    # If no direct match, check each prefix
    for prefix, mapped_service in service_prefixes.items():
        if service.startswith(prefix):
            return mapped_service
            
    # If no mapping found, return the original service name
    return service

def execute_query(athena, sql_query):
    """Execute Athena query and return execution ID"""
    result = athena.start_query_execution(
        QueryString=sql_query,
        ResultConfiguration={
            'OutputLocation': 's3://aws-athena-query-results-us-east-1-236223658093/',
        },
        WorkGroup='primary'
    )
    return result['QueryExecutionId']

def print_columns(in_use, not_in_use, unapproved):
    """Print results in three columns"""
    max_len = max(len(in_use), len(not_in_use), len(unapproved))
    fmt = "{:<35}{:<35}{:<35}"
    
    print("\n" + fmt.format(
        f"Approved In Use ({len(in_use)})",
        f"Approved Not In Use ({len(not_in_use)})",
        f"Unapproved In Use ({len(unapproved)})"
    ))
    print("-" * 105)
    
    for i in range(max_len):
        in_use_svc = list(sorted(in_use))[i] if i < len(in_use) else ""
        not_in_use_svc = list(sorted(not_in_use))[i] if i < len(not_in_use) else ""
        unapproved_svc = list(sorted(unapproved))[i] if i < len(unapproved) else ""
        print(fmt.format(in_use_svc, not_in_use_svc, unapproved_svc))
    print("")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Analyze AWS service usage from CloudTrail logs')
    parser.add_argument('--query-id', help='Reuse results from a previous query')
    args = parser.parse_args()

    # Verify account
    this_account_id = boto3.client("sts").get_caller_identity()["Account"]
    if this_account_id != '236223658093':
        print("\nThis program should be run via CloudShell in the us-security account\n")
        sys.exit(1)

    # Initialize Athena client
    athena = boto3.client('athena')

    if args.query_id:
        execution_id = args.query_id
        print(f"\nReusing results from query execution ID: {execution_id}")
    else:
        # Get the previous month
        last_month = (datetime.datetime.now() - relativedelta(months=1)).strftime('%Y/%m')
        
        # Simple query to get distinct eventSources
        sql_query = f"""
        SELECT DISTINCT eventsource 
        FROM "prod-cloudtraildb"."prod-cloudtraillogs" 
        WHERE day LIKE '{last_month}/%' 
        AND readonly='false'
        AND eventsource != 'portal.amazonaws.com'
        """
        
        print(f"\n\nUsing SQL query: {sql_query}\n")

        # Execute query
        execution_id = execute_query(athena, sql_query)
        status = "RUNNING"
        print(f"\nQuerying CloudTrail for services in use (Athena query execution ID {execution_id}) ...", end='')
        
        while status == "RUNNING":
            time.sleep(2)
            status = athena.get_query_execution(QueryExecutionId=execution_id)['QueryExecution']['Status']['State']
            print(".", end='')
        print(". (Done)")

    # Get results
    services_in_use = set()
    for page in athena.get_paginator('get_query_results').paginate(QueryExecutionId=execution_id):
        for row in page['ResultSet']['Rows']:
            if row['Data'][0]['VarCharValue'] != 'eventsource':  # Skip header row
                eventSource = row['Data'][0]['VarCharValue']
                service = normalize_eventSource(eventSource)
                services_in_use.add(service)

    # Create sets for comparison
    approved_services_set = set(approved_services)
    approved_in_use = services_in_use.intersection(approved_services_set)
    unapproved_in_use = {s for s in services_in_use if s not in approved_services_set}
    not_in_use = approved_services_set - approved_in_use

    # Print results
    print_columns(approved_in_use, not_in_use, unapproved_in_use)
    
    # Print the query ID for reuse
    print(f"\nTo reuse these results, run with: --query-id {execution_id}\n")

if __name__ == "__main__":
    main()
