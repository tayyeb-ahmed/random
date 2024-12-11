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

# Service mapping dictionary to convert CloudTrail eventSource to AWS service names
service_mapping = {
    "rolesanywhere.amazonaws.com": "AWS::IAM",
    "elasticloadbalancing.amazonaws.com": "AWS::EC2",
    "acm-pca.amazonaws.com": "AWS::ACMPCA",
    "monitoring.amazonaws.com": "AWS::CloudWatch",
    "logs.amazonaws.com": "AWS::CloudWatch",
    "sts.amazonaws.com": "AWS::IAM",
    "inspector2.amazonaws.com": "AWS::InspectorV2",
    "elasticfilesystem.amazonaws.com": "AWS::EFS",
    "organizations.amazonaws.com": "AWS::Organizations",
    "organization.amazonaws.com": "AWS::Organizations",
    "schemas.amazonaws.com": "AWS::EventSchemas",
    "transfer.amazonaws.com": "AWS::TransferFamily",
    "resource-groups.amazonaws.com": "AWS::ResourceGroups",
    "resourcegroups.amazonaws.com": "AWS::ResourceGroups",
    "support.amazonaws.com": "AWS::Support",
    "q.amazonaws.com": "AWS::Q",
    "fsx.amazonaws.com": "AWS::FSx",
    "cloudshell.amazonaws.com": "AWS::CloudShell",
    "signin.amazonaws.com": "AWS::IAM",
    "tagging.amazonaws.com": "AWS::ResourceGroupsAndTagEditor",
    "tag.amazonaws.com": "AWS::ResourceGroupsAndTagEditor"
}

# Consolidated approved services list
approved_services = [
    "AWS::ACM", "AWS::ACMPCA", "AWS::AccessAnalyzer", "AWS::ApiGateway", 
    "AWS::ApiGatewayV2", "AWS::AppConfig", "AWS::AppStream", "AWS::Athena", 
    "AWS::AuditManager", "AWS::AutoScaling", "AWS::Backup", "AWS::Batch", 
    "AWS::Cassandra", "AWS::CloudFormation", "AWS::CloudFront", "AWS::CloudTrail", 
    "AWS::CloudWatch", "AWS::CloudShell", "AWS::Cloud9", "AWS::CodeDeploy", "AWS::Config", 
    "AWS::DynamoDB", "AWS::EC2", "AWS::ECR", "AWS::ECS", "AWS::EFS", 
    "AWS::ElasticLoadBalancingV2", "AWS::EventSchemas", "AWS::Events", 
    "AWS::FSx", "AWS::Glue", "AWS::GuardDuty", "AWS::IAM", "AWS::InspectorV2", 
    "AWS::KMS", "AWS::Kinesis", "AWS::KinesisAnalyticsV2", "AWS::KinesisFirehose", 
    "AWS::Lambda", "AWS::MSK", "AWS::NetworkFirewall", "AWS::NetworkManager", 
    "AWS::OpenSearch", "AWS::Organizations", "AWS::QuickSight", "AWS::RDS", 
    "AWS::Redshift", "AWS::ResourceGroups", "AWS::ResourceGroupsAndTagEditor",
    "AWS::Route53", "AWS::Route53Resolver", "AWS::S3", "AWS::SES", "AWS::SNS", 
    "AWS::SQS", "AWS::SSM", "AWS::SecretsManager", "AWS::ServiceDiscovery", 
    "AWS::StepFunctions", "AWS::Support", "AWS::TransferFamily", "AWS::WAFv2"
]

def normalize_service_name(eventsource):
    """Convert CloudTrail eventSource to normalized service name with AWS:: prefix"""
    # Check if there's a mapping for this service
    if eventsource in service_mapping:
        return service_mapping[eventsource]
    # If no mapping exists, return the service name with AWS:: prefix
    service = eventsource.replace(".amazonaws.com", "").upper()
    return f"AWS::{service}"

def get_all_approved_services():
    """Get a list of all approved services (they're already in the correct format)"""
    return set(approved_services)

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
        in_use_svc = list(sorted(in_use))[i].replace("AWS::", "") if i < len(in_use) else ""
        not_in_use_svc = list(sorted(not_in_use))[i].replace("AWS::", "") if i < len(not_in_use) else ""
        unapproved_svc = list(sorted(unapproved))[i].replace("AWS::", "") if i < len(unapproved) else ""
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

    # Get all approved services
    all_approved_services = get_all_approved_services()

    # Categorize services
    approved_services_in_use = services_in_use.intersection(all_approved_services)
    unapproved_services_in_use = services_in_use - all_approved_services
    approved_services_not_in_use = all_approved_services - services_in_use

    # Print results in columns
    print_columns(approved_services_in_use, approved_services_not_in_use, unapproved_services_in_use)

if __name__ == "__main__":
    main()
