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
    "schemas.amazonaws.com": "EventSchemas",
    "transfer.amazonaws.com": "Transfer",
    "resource-groups.amazonaws.com": "ResourceGroups",
    "support.amazonaws.com": "Support",
    "q.amazonaws.com": "Q",
    "fsx.amazonaws.com": "FSx",
    "cloudshell.amazonaws.com": "CloudShell",
    "signin.amazonaws.com": "IAM"
}

approved_services = ["AWS::ACM", "AWS::ACMPCA", "AWS::AccessAnalyzer", "AWS::ApiGateway", 
                    "AWS::ApiGatewayV2", "AWS::AppConfig", "AWS::AppStream", "AWS::Athena", 
                    "AWS::AuditManager", "AWS::AutoScaling", "AWS::Backup", "AWS::Batch", 
                    "AWS::Cassandra", "AWS::CloudFormation", "AWS::CloudFront", "AWS::CloudTrail", 
                    "AWS::CloudWatch", "AWS::Cloud9", "AWS::CodeDeploy", "AWS::Config", 
                    "AWS::DynamoDB", "AWS::EC2", "AWS::ECR", "AWS::ECS", "AWS::EFS", 
                    "AWS::ElasticLoadBalancingV2", "AWS::EventSchemas", "AWS::Events", 
                    "AWS::Glue", "AWS::GuardDuty", "AWS::IAM", "AWS::InspectorV2", 
                    "AWS::KMS", "AWS::Kinesis", "AWS::KinesisAnalyticsV2", "AWS::KinesisFirehose", 
                    "AWS::Lambda", "AWS::MSK", "AWS::NetworkFirewall", "AWS::NetworkManager", 
                    "AWS::OpenSearch", "AWS::QuickSight", "AWS::RDS", "AWS::Redshift", 
                    "AWS::Route53", "AWS::Route53Resolver", "AWS::S3", "AWS::SES", 
                    "AWS::SNS", "AWS::SQS", "AWS::SSM", "AWS::SecretsManager", 
                    "AWS::ServiceDiscovery", "AWS::StepFunctions", "AWS::WAFv2"]

additional_approved_services = ["elasticloadbalancing", "acm-pca", "monitoring", "logs", 
                              "sts", "inspector2", "elasticfilesystem", "organizations", 
                              "schemas", "transfer", "inspector2", "resource-groups", 
                              "support", "rolesanywhere", "q", "fsx", "cloudshell", "signin"]

def normalize_service_name(eventsource):
    """Convert CloudTrail eventSource to normalized service name"""
    # Remove .amazonaws.com suffix if present
    service = eventsource.replace(".amazonaws.com", "")
    # Check if there's a mapping for this service
    if eventsource in service_mapping:
        return service_mapping[eventsource]
    # If no mapping exists, return the service name in uppercase
    return service.upper()

def get_all_approved_services():
    """Get a list of all approved services in normalized format"""
    normalized_services = set()
    # Process AWS::Service format
    for service in approved_services:
        service_name = service.split("::")[1].upper()
        normalized_services.add(service_name)
    # Process additional services
    for service in additional_approved_services:
        if f"{service}.amazonaws.com" in service_mapping:
            normalized_services.add(service_mapping[f"{service}.amazonaws.com"])
        else:
            normalized_services.add(service.upper())
    return normalized_services

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
    print(". (Done)\n")

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

    # Print results
    print(f"\nApproved services in use ({len(approved_services_in_use)}):\n")
    for service in sorted(approved_services_in_use):
        print(f"    {service}")

    print(f"\nApproved services NOT in use ({len(approved_services_not_in_use)}):\n")
    for service in sorted(approved_services_not_in_use):
        print(f"    {service}")

    print(f"\nUnapproved services in use ({len(unapproved_services_in_use)}):\n")
    for service in sorted(unapproved_services_in_use):
        print(f"    {service}")

    print("")

if __name__ == "__main__":
    main()
