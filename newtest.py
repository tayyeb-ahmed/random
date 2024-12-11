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

# Consolidated approved services list
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

def get_service_info(athena, last_month):
    """Query CloudTrail and process the results to get unique services"""
    sql_query = f"""
    SELECT DISTINCT
        COALESCE(
            userIdentity.invokedBy,
            CASE
                WHEN eventSource LIKE 'sts.%' THEN 'IAM'
                WHEN eventSource LIKE 'signin.%' THEN 'IAM'
                WHEN eventSource LIKE 'monitoring.%' THEN 'CloudWatch'
                WHEN eventSource LIKE 'logs.%' THEN 'CloudWatch'
                WHEN eventSource LIKE 'elasticloadbalancing.%' THEN 'EC2'
                WHEN eventSource LIKE 'firehose.%' THEN 'KinesisFirehose'
                WHEN eventSource LIKE 'kinesis.%' THEN 'Kinesis'
                WHEN eventSource LIKE 'analyticsv2.%' THEN 'KinesisAnalyticsV2'
                ELSE REGEXP_REPLACE(
                    REGEXP_REPLACE(eventSource, '\\.amazonaws\\.com$', ''),
                    '^([a-z0-9])',
                    UPPER(REGEXP_EXTRACT(eventSource, '^([a-z0-9])', 1))
                )
            END
        ) as service_name
    FROM "prod-cloudtraildb"."prod-cloudtraillogs"
    WHERE day LIKE '{last_month}/%'
        AND readonly='false'
        AND eventSource != 'portal.amazonaws.com'  -- Exclude portal events
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
    services = set()
    for page in athena.get_paginator('get_query_results').paginate(QueryExecutionId=execution_id):
        for row in page['ResultSet']['Rows']:
            if row['Data'][0]['VarCharValue'] != 'service_name':  # Skip header row
                services.add(row['Data'][0]['VarCharValue'])
    
    return services

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

    # Get services from CloudTrail
    services_in_use = get_service_info(athena, last_month)

    # Create lookup for approved services (case-insensitive)
    approved_services_lookup = {s.lower(): s for s in approved_services}
    
    # Categorize services using case-insensitive comparison
    approved_in_use = set()
    unapproved_in_use = set()
    
    for service in services_in_use:
        if service.lower() in approved_services_lookup:
            approved_in_use.add(approved_services_lookup[service.lower()])
        else:
            unapproved_in_use.add(service)
    
    # Get services not in use
    approved_not_in_use = {s for s in approved_services if s not in approved_in_use}

    # Print results in columns
    print_columns(approved_in_use, approved_not_in_use, unapproved_in_use)

if __name__ == "__main__":
    main()
