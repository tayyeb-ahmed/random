#!/usr/bin/python3 -u

#
# Get the list of services accessed in a particular time period
#

import sys,boto3,time,json,datetime
from dateutil.relativedelta import relativedelta

approved_services = [ "AWS::ACM", "AWS::ACMPCA", "AWS::AccessAnalyzer", "AWS::ApiGateway", "AWS::ApiGatewayV2", "AWS::AppConfig", "AWS::AppStream",  "AWS::Athena", "AWS::AuditManager", "AWS::AutoScaling", "AWS::Backup", "AWS::Batch", "AWS::Cassandra", "AWS::CloudFormation", "AWS::CloudFront", "AWS::CloudTrail", "AWS::CloudWatch", "AWS::Cloud9",  "AWS::CodeDeploy", "AWS::Config", "AWS::DynamoDB", "AWS::EC2", "AWS::ECR", "AWS::ECS", "AWS::EFS", "AWS::ElasticLoadBalancingV2", "AWS::EventSchemas", "AWS::Events", "AWS::Glue", "AWS::GuardDuty", "AWS::IAM", "AWS::InspectorV2", "AWS::KMS", "AWS::Kinesis", "AWS::KinesisAnalyticsV2", "AWS::KinesisFirehose", "AWS::Lambda", "AWS::MSK", "AWS::NetworkFirewall", "AWS::NetworkManager", "AWS::OpenSearch", "AWS::QuickSight", "AWS::RDS", "AWS::Redshift", "AWS::Route53", "AWS::Route53Resolver", "AWS::S3", "AWS::SES", "AWS::SNS", "AWS::SQS", "AWS::SSM", "AWS::SecretsManager", "AWS::ServiceDiscovery", "AWS::StepFunctions", "AWS::WAFv2" ]

additional_approved_services = [ "elasticloadbalancing", "acm-pca", "monitoring", "logs", "sts", "inspector2", "elasticfilesystem", "organizations", "schemas", "transfer", "inspector2", "resource-groups", "support",  "rolesanywhere", "q", "fsx", "cloudshell", "signin" ]

# Get the previous month to this month in YYYY/MM format
last_month=(datetime.datetime.now() - relativedelta(months=1)).strftime('%Y/%m')


sql_query = f"SELECT DISTINCT eventsource FROM \"prod-cloudtraildb\".\"prod-cloudtraillogs\" WHERE day LIKE '{last_month}/%' and readonly='false'"

def execute_query():
    result = athena.start_query_execution(
        QueryString=sql_query,
        ResultConfiguration={
            'OutputLocation': 's3://aws-athena-query-results-us-east-1-236223658093/',
        },
        WorkGroup='primary'
    )
    request_id = result['ResponseMetadata']['RequestId']
    query_execution_id = result['QueryExecutionId']
    return query_execution_id


this_account_id = boto3.client("sts").get_caller_identity()["Account"]
if this_account_id != '236223658093':
   print("\nThis program should be run via CloudShell in the us-security account\n")
   sys.exit(1)

athena = boto3.client('athena')

print(f"\n\nUsing SQL query: {sql_query}\n")

if True:
    execution_id = execute_query()
else:
    execution_id = 'f659f6fb-dede-4f4d-874d-8c041c078fcd'
status = "RUNNING"
print(f"\nQuerying CloudTrail for services in use (Athena query execution ID {execution_id}) ...", end='')
while status == "RUNNING":
    time.sleep(2)
    status = athena.get_query_execution(QueryExecutionId=execution_id)['QueryExecution']['Status']['State']
    print(".", end='')
print(". (Done)\n")
results = []
for page in athena.get_paginator('get_query_results').paginate(QueryExecutionId=execution_id):
    for row in  page['ResultSet']['Rows']:
        results.append(row)
services_in_use = []
for row in results:
    service = row['Data'][0]['VarCharValue']
    if service != "eventsource":
        services_in_use.append(service)
all_approved_services = additional_approved_services
approved_services_in_use = []
unapproved_services_in_use = []
for service in approved_services:
    all_approved_services.append(service.split("::")[1].lower())
for service in services_in_use:
    if service.replace(".amazonaws.com", "") not in all_approved_services:
        unapproved_services_in_use.append(service)
    else:
        approved_services_in_use.append(service)

print(f"\nApproved services in use ({len(approved_services_in_use)}):\n")
for service in approved_services_in_use:
    print(f"    {service}")
print(f"\nUnapproved services in use ({len(unapproved_services_in_use)}):\n")
for service in unapproved_services_in_use:
    print(f"    {service}")

print("")
