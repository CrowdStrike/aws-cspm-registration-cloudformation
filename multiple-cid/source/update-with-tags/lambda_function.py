"""Force Update for Multiple CID CSPM StackSets"""
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CSPM_TEMPLATE_URL = os.environ['cspm_template_url']
ADMIN_ROLE_ARN = os.environ['admin_role_arn']
EXEC_ROLE_NAME = os.environ['exec_role_arn']
KEY_1 = os.environ['key1']
KEY_2 = os.environ['key2']
KEY_3 = os.environ['key3']
VALUE_1 = os.environ['value1']
VALUE_2 = os.environ['value2']
VALUE_3 = os.environ['value3']

def get_stacksets():
    try:
        stackset_names = []
        client = boto3.client('cloudformation')
        response = client.list_stack_sets(
            Status='ACTIVE'
        )
        summaries = response['Summaries']
        next_token = response.get('NextToken', None)
        while next_token:
            response = client.list_stack_sets(
                Status='ACTIVE',
                NextToken=next_token
            )
            summaries += response['Summaries']
            next_token = response.get('NextToken', None)
        for i in summaries:
            stackset_name = i['StackSetName']
            if 'CrowdStrike-Cloud-Security-Stackset-' in stackset_name:
                stackset_names.append(stackset_name)
        return stackset_names
    except ClientError as error:
        raise error

def update_stacksets(stackset_name):
    try:
        client = boto3.client('cloudformation')
        response = client.update_stack_set(
            StackSetName=stackset_name,
            TemplateURL=CSPM_TEMPLATE_URL,
            Capabilities=[
                'CAPABILITY_NAMED_IAM',
            ],
            AdministrationRoleARN=ADMIN_ROLE_ARN,
            ExecutionRoleName=EXEC_ROLE_NAME,
            Parameters=[
                {
                    'ParameterKey': 'APICredentialsStorageMode',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'ClientID',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'ClientSecret',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'CSAccountNumber',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'CSBucketName',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'CSEventBusName',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'CSRoleName',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'DSPMRegions',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'DSPMRoleName',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'EnableDSPM',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'EnableIdentityProtection',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'EnableIOA',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'EnableIOM',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'EnableSensorManagement',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'ExternalID',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'PermissionsBoundary',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'RoleName',
                    'UsePreviousValue': True
                },
                {
                    'ParameterKey': 'UseExistingCloudtrail',
                    'UsePreviousValue': True
                }
            ],
            Tags=[
                {
                    'Key': KEY_1,
                    'Value': VALUE_1
                },
                {
                    'Key': KEY_2,
                    'Value': VALUE_2
                },
                {
                    'Key': KEY_3,
                    'Value': VALUE_3
                }
            ],
        )
        print(response)
    except ClientError as error:
        raise error

def lambda_handler(event, context):
    """Main Function"""
    logger.info('Got event %s', event)
    logger.info('Context %s', context)
    stackset_names = get_stacksets()
    print(stackset_names)
    for stackset_name in stackset_names:
        update_stacksets(stackset_name)
