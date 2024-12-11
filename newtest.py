#!/usr/bin/python3 -u
#
# Get the list of services accessed in a particular time period and compare with approved services
#
import sys
import boto3
import time
import json
import datetime
from dateutil.relativedelta import relativedelta

# Service mapping dictionary to convert CloudTrail eventSource to service names
service_mapping = {
    "rolesanywhere.amazonaws.com": "IAM",
    "elasticloadbalancing.amazonaws.com": "EC2",
    "acm-pca.amazonaws.com": "ACMPCA",
    "monitoring.amazonaws.com": "CloudWatch",
    "logs.amazonaws.com": "CloudWatch",
    "sts.amazonaws.com": "IAM",
    "inspector2.amazonaws.com": "InspectorV2",
    "elasticfilesystem.amazonaws.com": "EFS",
    "organizations.amazonaws.com": "Organizations",
    "organization.amazonaws.com": "Organizations",
    "schemas.amazonaws.com": "EventSchemas",
    "transfer.amazonaws.com": "TransferFamily",
    "resource-groups.amazonaws.com": "ResourceGroups",
    "resourcegroups.amazonaws.com": "ResourceGroups",
    "support.amazonaws.com": "Support",
    "q.amazonaws.com": "Q",
    "fsx.amazonaws.com": "FSx",
    "cloudshell.amazonaws.com": "CloudShell",
    "signin.amazonaws.com": "IAM",
    "tagging.amazonaws.com": "ResourceGroupsAndTagEditor",
    "tag.amazonaws.com": "ResourceGroupsAndTagEditor"
}

# Consolidated approved services list - simplified without AWS:: prefix
approved_services = [
    "ACM", "ACMPCA", "AccessAnalyzer", "ApiGateway", "ApiGatewayV2", 
    "AppConfig", "AppStream", "Athena", "AuditManager", "AutoScaling", 
    "Backup", "Batch", "Cassandra", "CloudFormation", "CloudFront", 
    "CloudTrail", "CloudWatch", "CloudShell", "Cloud9", "CodeDeploy", 
    "Config", "DynamoDB", "EC2", "ECR", "ECS", "EFS", 
    "ElasticLoadBalancingV2", "EventSchemas", "Events", "FSx", "Glue", 
    "GuardDuty", "IAM", "InspectorV2", "KMS", "Kinesis", 
    "KinesisAnalyticsV2", "KinesisFirehose", "Lambda", "MSK", 
    "NetworkFirewall", "NetworkManager", "OpenSearch", "Organizations", 
    "QuickSight", "RDS", "Redshift", "ResourceGroups", 
    "ResourceGroupsAndTagEditor", "Route53", "Route53Resolver", "S3", 
    "SES", "SNS", "SQS", "SSM", "SecretsManager", "ServiceDiscovery", 
    "StepFunctions", "Support", "TransferFamily", "WAFv2"
]

def normalize_service_name(eventsource):
    """Convert CloudTrail eventSource to normalized service name"""
    # Check if there's a mapping for this service
    if eventsource in service_mapping:
        return service_mapping[eventsource]
    # If no mapping exists, return the service name without domain
    return eventsource.replace(".amazonaws.com", "").upper()

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
    # Get the maximum length for each column
    max_len = max(len(in_use), len(not_in_use), len(unapproved))
    
    # Create format string for columns (35 chars wide each)
    fmt = "{:<35}{:<35}{:<35}"
    
    # Print headers
    print("\n" + fmt.format(
        f"Approved In Use ({len(in_use)})",
        f"Approved Not In Use ({len(not_in_use)})",
        f"Unapproved In Use ({len(unapproved)})"
    ))
    print("-" * 105)  # Separator line
    
    # Print rows
    for i in range(max_len):
        in_use_svc = list(sorted(in_use))[i] if i < len(in_use) else ""
        not_in_use_svc = list(sorted(not_in_use))[i] if i < len(not_in_use) else ""
        unapproved_svc = list(sorted(unapproved))[i] if i < len(unapproved) else ""
        print(fmt.format(in_use_svc, not_in_use_svc, unapproved_svc))
    print("")

def main():
    # Verify account
    this_account_id = boto3.client("sts").get_caller_identity()["Account"]
    if this_account_id != '236223658093':
        print("\nThis program should be run via CloudShell in the us-security account\n")
        sys.exit(1)

    # Initialize Athena client
    athena = boto3.client('athena')

    # Get the previous month
    last_month = (datetime.datetime.now() - relativedelta(months=1)).strftime('%Y/%m')
    sql_query = f"SELECT DISTINCT eventsource FROM \"prod-cloudtraildb\".\"prod-cloudtraillogs\" WHERE day LIKE '{last_month}/%' and readonly='false'"
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
    results = []
    for page in athena.get_paginator('get_query_results').paginate(QueryExecutionId=execution_id):
        for row in page['ResultSet']['Rows']:
            results.append(row)

    # Process services
    services_in_use = set()
    for row in results:
        service = row['Data'][0]['VarCharValue']
        if service != "eventsource":
            normalized_service = normalize_service_name(service)
            services_in_use.add(normalized_service)

    # Convert approved services to set for comparison
    all_approved_services = set(approved_services)

    # Categorize services
    approved_services_in_use = services_in_use.intersection(all_approved_services)
    unapproved_services_in_use = services_in_use - all_approved_services
    approved_services_not_in_use = all_approved_services - services_in_use

    # Print results in columns
    print_columns(approved_services_in_use, approved_services_not_in_use, unapproved_services_in_use)

if __name__ == "__main__":
    main()
