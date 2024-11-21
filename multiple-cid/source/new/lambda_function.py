"""Register New AWS Accounts with Multiple CrowdStrike CIDs"""
import json
import logging
import os
import sys
import subprocess
import base64
import datetime
import boto3
from botocore.exceptions import ClientError

os.chdir('/tmp')
requirements = open("requirements.txt", "x", encoding="utf-8")
requirements = open("requirements.txt", "a", encoding="utf-8")
requirements.write("urllib3<2")
requirements = open("requirements.txt", "a", encoding="utf-8")
requirements.write("requests==2.31.0")
# pip install falconpy package to /tmp/ and add to path
subprocess.call('pip install crowdstrike-falconpy -r /tmp/requirements.txt -t /tmp/ --no-cache-dir'.split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
               )
sys.path.insert(1, '/tmp/')
from falconpy import CSPMRegistration
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# CONSTANTS
SUCCESS = "SUCCESS"
FAILED = "FAILED"

VERSION = "1.1.0"
NAME = "crowdstrike-cloud-reg-multi-cid"
USER_AGENT = ("%s/%s" % (NAME, VERSION))

EXISTING_CLOUDTRAIL = eval(os.environ['existing_cloudtrail'])
SENSOR_MANAGEMENT = eval(os.environ['sensor_management'])
CREDENTIALS_STORAGE = os.environ['credentials_storage']
AWS_ACCOUNT_TYPE = os.environ['aws_account_type']
AWS_REGION = os.environ['current_region']
SECRET_LIST = os.environ['secret_list']
STACKSET_ADMIN_ROLE = os.environ['admin_role']
STACKSET_EXEC_ROLE = os.environ['exec_role']
ENABLE_IOA = eval(os.environ['enable_ioa'])
S3_BUCKET = os.environ['s3_bucket']
REGIONS = os.environ['regions']

def get_secret(secret_name, secret_region):
    """Retrieve Falcon API Credentials from Secrets Manager"""
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=secret_region
    )
    logger.info(secret_name)
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as error:
        raise error
    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
    else:
        secret = base64.b64decode(get_secret_value_response['SecretBinary'])
    return secret

def register_account(account, falcon_client_id, falcon_secret, falcon_cloud):
    """Register AWS Account with Falcon CSPM"""
    falcon = CSPMRegistration(client_id=falcon_client_id,
                            client_secret=falcon_secret,
                            base_url=falcon_cloud,
                            user_agent=USER_AGENT
                            )
    if EXISTING_CLOUDTRAIL:
        response = falcon.create_aws_account(account_id=account,
                                            account_type=AWS_ACCOUNT_TYPE,
                                            behavior_assessment_enabled=True,
                                            sensor_management_enabled=True,
                                            use_existing_cloudtrail=EXISTING_CLOUDTRAIL,
                                            user_agent=USER_AGENT
                                            )
    else:
        response = falcon.create_aws_account(account_id=account,
                                            account_type=AWS_ACCOUNT_TYPE,
                                            behavior_assessment_enabled=True,
                                            sensor_management_enabled=True,
                                            use_existing_cloudtrail=EXISTING_CLOUDTRAIL,
                                            aws_cloudtrail_region=AWS_REGION,
                                            user_agent=USER_AGENT
                                            )
    logger.info('Response: %s', response)
    return response

def add_stack_instance(account,
                       iam_role_name,
                       external_id,
                       cs_role_name,
                       cs_account_id,
                       cs_bucket_name,
                       cs_eventbus_name,
                       falcon_client_id,
                       falcon_secret,
                       existing_cloudtrail,
                       sensor_management,
                       enable_ioa
                      ):
    """Create CloudFormation StackSet"""
    now = datetime.datetime.now()
    timestamp = now.strftime("%m%d%y%H%M%S")

    session = boto3.session.Session()
    client = session.client(
        service_name='cloudformation',
        region_name=AWS_REGION
    )

    client.create_stack_set(
        StackSetName=f'CrowdStrike-Cloud-Security-Stackset-{account}',
        Description='StackSet to onboard accounts with CrowdStrike',
        TemplateURL='https://cs-prod-cloudconnect-templates.s3-us-west-1.amazonaws.com/aws_cspm_cloudformation_lambda_v2.json',
        Parameters=[
            {
                'ParameterKey': 'RoleName',
                'ParameterValue': str(iam_role_name),
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'ExternalID',
                'ParameterValue': str(external_id),
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'CSRoleName',
                'ParameterValue': str(cs_role_name),
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'CSAccountNumber',
                'ParameterValue': str(cs_account_id),
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'CSBucketName',
                'ParameterValue': cs_bucket_name,
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'CSEventBusName',
                'ParameterValue': cs_eventbus_name,
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'ClientID',
                'ParameterValue': falcon_client_id,
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'ClientSecret',
                'ParameterValue': falcon_secret,
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'EnableIOA',
                'ParameterValue': enable_ioa,
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'UseExistingCloudtrail',
                'ParameterValue': existing_cloudtrail,
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'EnableSensorManagement',
                'ParameterValue': sensor_management,
                'UsePreviousValue': False,
            },
            {
                'ParameterKey': 'APICredentialsStorageMode',
                'ParameterValue': str(CREDENTIALS_STORAGE),
                'UsePreviousValue': False,
            }
        ],
        Capabilities=['CAPABILITY_NAMED_IAM'],
        AdministrationRoleARN=STACKSET_ADMIN_ROLE,
        ExecutionRoleName=STACKSET_EXEC_ROLE,
        PermissionModel='SELF_MANAGED',
        CallAs='SELF',
    )

    client.create_stack_instances(
        StackSetName=f'CrowdStrike-Cloud-Security-Stackset-{account}',
        Accounts=[account],
        Regions=[AWS_REGION],
        OperationPreferences={
            'FailureTolerancePercentage': 100,
            'MaxConcurrentPercentage': 100,
            'ConcurrencyMode': 'SOFT_FAILURE_TOLERANCE'
        },
        OperationId=f'{account}-{timestamp}',
        CallAs='SELF'
    )

def gov_gov_stacksets(my_regions,
                      account,
                      iam_role_name,
                      external_id,
                      cs_role_name,
                      cs_account_id,
                      cs_bucket_name,
                      cs_eventbus_name,
                      falcon_client_id,
                      falcon_secret,
                      existing_cloudtrail,
                      sensor_management,
                      enable_ioa
                    ):
    """Create CloudFormation Stacksets for Gov to Gov"""
    now = datetime.datetime.now()
    timestamp = now.strftime("%m%d%y%H%M%S")

    session = boto3.session.Session()
    client = session.client(
        service_name='cloudformation',
        region_name=AWS_REGION
    )
    if not EXISTING_CLOUDTRAIL:
        client.create_stack_set(
            StackSetName=f'CrowdStrike-Cloud-Security-Stackset-{account}',
            Description='Stackset to onboard account with CrowdStrike Cloud Security',
            TemplateURL=f'https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/crowdstrike_aws_gov_cspm.json',
            Parameters=[
                {
                    'ParameterKey': 'RoleName',
                    'ParameterValue': iam_role_name,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ExternalID',
                    'ParameterValue': external_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSRoleName',
                    'ParameterValue': cs_role_name,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSAccountNumber',
                    'ParameterValue': cs_account_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'EnableIOA',
                    'ParameterValue': enable_ioa,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ClientID',
                    'ParameterValue': falcon_client_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ClientSecret',
                    'ParameterValue': falcon_secret,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'UseExistingCloudtrail',
                    'ParameterValue': existing_cloudtrail,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'EnableSensorManagement',
                    'ParameterValue': sensor_management,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'APICredentialsStorageMode',
                    'ParameterValue': CREDENTIALS_STORAGE,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSBucketName',
                    'ParameterValue': cs_bucket_name,
                    'UsePreviousValue': False,
                }
            ],
            Capabilities=[
                'CAPABILITY_NAMED_IAM'
            ],
            AdministrationRoleARN=STACKSET_ADMIN_ROLE,
            ExecutionRoleName=STACKSET_EXEC_ROLE,
            PermissionModel='SELF_MANAGED',
            CallAs='SELF',
        )
    else:
        client.create_stack_set(
            StackSetName=f'CrowdStrike-Cloud-Security-Stackset-{account}',
            Description='Stackset to onboard account with CrowdStrike Cloud Security',
            TemplateURL=f'https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/crowdstrike_aws_gov_cspm.json',
            Parameters=[
                {
                    'ParameterKey': 'RoleName',
                    'ParameterValue': iam_role_name,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ExternalID',
                    'ParameterValue': external_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSRoleName',
                    'ParameterValue': cs_role_name,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSAccountNumber',
                    'ParameterValue': cs_account_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'EnableIOA',
                    'ParameterValue': enable_ioa,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ClientID',
                    'ParameterValue': falcon_client_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ClientSecret',
                    'ParameterValue': falcon_secret,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'UseExistingCloudtrail',
                    'ParameterValue': existing_cloudtrail,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'EnableSensorManagement',
                    'ParameterValue': sensor_management,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'APICredentialsStorageMode',
                    'ParameterValue': CREDENTIALS_STORAGE,
                    'UsePreviousValue': False,
                }
            ],
            Capabilities=[
                'CAPABILITY_NAMED_IAM'
            ],
            AdministrationRoleARN=STACKSET_ADMIN_ROLE,
            ExecutionRoleName=STACKSET_EXEC_ROLE,
            PermissionModel='SELF_MANAGED',
            CallAs='SELF',
        )

    client.create_stack_instances(
        StackSetName=f'CrowdStrike-Cloud-Security-Stackset-{account}',
        Accounts=[account],
        Regions=[AWS_REGION],
        OperationPreferences={
            'FailureTolerancePercentage': 100,
            'MaxConcurrentPercentage': 100,
            'ConcurrencyMode': 'SOFT_FAILURE_TOLERANCE'
        },
        OperationId=f'{account}-{timestamp}',
        CallAs='SELF'
    )

    client.create_stack_set(
        StackSetName=f'CrowdStrike-Cloud-Security-EB-Stackset-{account}',
        Description='Stackset to onboard account with CrowdStrike Cloud Security IOAs',
        TemplateURL='https://cs-csgov-laggar-cloudconnect-templates.s3-us-gov-west-1.amazonaws.com/aws_cspm_cloudformation_eb_v2.json',
        Parameters=[
            {
                'ParameterKey': 'CSAccountNumber',
                'ParameterValue': cs_account_id,
                'UsePreviousValue': False
            },
            {
                'ParameterKey': 'CSEventBusName',
                'ParameterValue': cs_eventbus_name,
                'UsePreviousValue': False
            }
        ],
        Capabilities=[
            'CAPABILITY_NAMED_IAM'
        ],
        AdministrationRoleARN=STACKSET_ADMIN_ROLE,
        ExecutionRoleName=STACKSET_EXEC_ROLE,
        PermissionModel='SELF_MANAGED',
        CallAs='SELF',
    )

    client.create_stack_instances(
        StackSetName=f'CrowdStrike-Cloud-Security-EB-Stackset-{account}',
        Accounts=[account],
        Regions=my_regions,
        OperationPreferences={
            'FailureTolerancePercentage': 100,
            'MaxConcurrentPercentage': 100,
            'ConcurrencyMode': 'SOFT_FAILURE_TOLERANCE'
        },
        OperationId=f'{account}-{timestamp}',
        CallAs='SELF'
    )

def comm_gov_stacksets(account,
                       iam_role_name,
                       external_id,
                       cs_role_name,
                       cs_account_id,
                       cs_bucket_name,
                       falcon_client_id,
                       falcon_secret,
                       existing_cloudtrail,
                       sensor_management,
                       comm_gov_eb_regions
                      ):
    """Create CloudFormation StackSets for Commercial to Gov"""
    now = datetime.datetime.now()
    timestamp = now.strftime("%m%d%y%H%M%S")

    session = boto3.session.Session()
    client = session.client(
        service_name='cloudformation',
        region_name=AWS_REGION
    )
    if not EXISTING_CLOUDTRAIL:
        client.create_stack_set(
            StackSetName=f'CrowdStrike-Cloud-Security-Stackset-{account}',
            Description='Stackset to onboard account with CrowdStrike Cloud Security',
            TemplateURL=f'https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/crowdstrike_aws_cspm.json',
            Parameters=[
                {
                    'ParameterKey': 'RoleName',
                    'ParameterValue': iam_role_name,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ExternalID',
                    'ParameterValue': external_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSRoleName',
                    'ParameterValue': cs_role_name,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSAccountNumber',
                    'ParameterValue': cs_account_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'EnableIOA',
                    'ParameterValue': 'false',
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ClientID',
                    'ParameterValue': falcon_client_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ClientSecret',
                    'ParameterValue': falcon_secret,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'UseExistingCloudtrail',
                    'ParameterValue': existing_cloudtrail,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'EnableSensorManagement',
                    'ParameterValue': sensor_management,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'APICredentialsStorageMode',
                    'ParameterValue': CREDENTIALS_STORAGE,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSBucketName',
                    'ParameterValue': cs_bucket_name,
                    'UsePreviousValue': False,
                }
            ],
            Capabilities=[
                'CAPABILITY_NAMED_IAM'
            ],
            AdministrationRoleARN=STACKSET_ADMIN_ROLE,
            ExecutionRoleName=STACKSET_EXEC_ROLE,
            PermissionModel='SELF_MANAGED',
            CallAs='SELF',
        )
    else:
        client.create_stack_set(
            StackSetName=f'CrowdStrike-Cloud-Security-Stackset-{account}',
            Description='Stackset to onboard account with CrowdStrike Cloud Security',
            TemplateURL=f'https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/crowdstrike_aws_cspm.json',
            Parameters=[
                {
                    'ParameterKey': 'RoleName',
                    'ParameterValue': iam_role_name,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ExternalID',
                    'ParameterValue': external_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSRoleName',
                    'ParameterValue': cs_role_name,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'CSAccountNumber',
                    'ParameterValue': cs_account_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'EnableIOA',
                    'ParameterValue': 'false',
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ClientID',
                    'ParameterValue': falcon_client_id,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'ClientSecret',
                    'ParameterValue': falcon_secret,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'UseExistingCloudtrail',
                    'ParameterValue': existing_cloudtrail,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'EnableSensorManagement',
                    'ParameterValue': sensor_management,
                    'UsePreviousValue': False,
                },
                {
                    'ParameterKey': 'APICredentialsStorageMode',
                    'ParameterValue': CREDENTIALS_STORAGE,
                    'UsePreviousValue': False,
                }
            ],
            Capabilities=[
                'CAPABILITY_NAMED_IAM'
            ],
            AdministrationRoleARN=STACKSET_ADMIN_ROLE,
            ExecutionRoleName=STACKSET_EXEC_ROLE,
            PermissionModel='SELF_MANAGED',
            CallAs='SELF',
        )

    client.create_stack_instances(
        StackSetName=f'CrowdStrike-Cloud-Security-Stackset-{account}',
        Accounts=[account],
        Regions=[AWS_REGION],
        OperationPreferences={
            'FailureTolerancePercentage': 100,
            'MaxConcurrentPercentage': 100,
            'ConcurrencyMode': 'SOFT_FAILURE_TOLERANCE'
        },
        OperationId=f'{account}-{timestamp}',
        CallAs='SELF'
    )

    client.create_stack_set(
        StackSetName=f'CrowdStrike-Cloud-Security-EB-Stackset-{account}',
        Description='Stackset to onboard account with CrowdStrike Cloud Security IOAs',
        TemplateURL='https://cs-prod-cloudconnect-templates.s3.amazonaws.com/aws_cspm_cloudformation_eb_gov_comm_v2.json',
        Parameters=[
            {
                'ParameterKey': 'DefaultEventBusRegion',
                'ParameterValue': AWS_REGION,
                'UsePreviousValue': False
            }
        ],
        Capabilities=[
            'CAPABILITY_NAMED_IAM'
        ],
        AdministrationRoleARN=STACKSET_ADMIN_ROLE,
        ExecutionRoleName=STACKSET_EXEC_ROLE,
        PermissionModel='SELF_MANAGED',
        CallAs='SELF',
    )

    client.create_stack_instances(
        StackSetName=f'CrowdStrike-Cloud-Security-EB-Stackset-{account}',
        Accounts=[account],
        Regions=comm_gov_eb_regions,
        OperationPreferences={
            'FailureTolerancePercentage': 100,
            'MaxConcurrentPercentage': 100,
            'ConcurrencyMode': 'SOFT_FAILURE_TOLERANCE'
        },
        OperationId=f'{account}-{timestamp}',
        CallAs='SELF'
    )

    client.create_stack_set(
        StackSetName=f'CrowdStrike-Cloud-Security-IOA-Stackset-{account}',
        Description='Stackset to onboard account with CrowdStrike Cloud Security IOAs',
        TemplateURL='https://cs-prod-cloudconnect-templates.s3.amazonaws.com/aws_cspm_cloudformation_gov_commercial_ioa_lambda_v2.json',
        Parameters=[
            {
                'ParameterKey': 'ClientID',
                'ParameterValue': falcon_client_id,
                'UsePreviousValue': False
            },
            {
                'ParameterKey': 'ClientSecret',
                'ParameterValue': falcon_secret,
                'UsePreviousValue': False
            }
        ],
        Capabilities=[
            'CAPABILITY_NAMED_IAM'
        ],
        AdministrationRoleARN=STACKSET_ADMIN_ROLE,
        ExecutionRoleName=STACKSET_EXEC_ROLE,
        PermissionModel='SELF_MANAGED',
        CallAs='SELF',
    )

    client.create_stack_instances(
        StackSetName=f'CrowdStrike-Cloud-Security-IOA-Stackset-{account}',
        Accounts=[account],
        Regions=[AWS_REGION],
        OperationPreferences={
            'FailureTolerancePercentage': 100,
            'MaxConcurrentPercentage': 100,
            'ConcurrencyMode': 'SOFT_FAILURE_TOLERANCE'
        },
        OperationId=f'{account}-{timestamp}',
        CallAs='SELF'
    )

def get_active_regions():
    """Retrieve Active Regions"""
    session = boto3.session.Session()
    client = session.client(
        service_name='ec2',
        region_name=AWS_REGION
    )
    active_regions = []
    my_regions = []
    comm_gov_eb_regions = []
    try:
        describe_regions_response = client.describe_regions(AllRegions=False)
        regions = describe_regions_response['Regions']
        for region in regions:
            active_regions += [region['RegionName']]
        for region in active_regions:
            if region in my_regions and region != AWS_REGION:
                comm_gov_eb_regions += [region]
        for region in active_regions:
            if region in REGIONS:
                my_regions += [region]
        return my_regions, comm_gov_eb_regions
    except ClientError as error:
        raise error

def lambda_handler(event, context):
    """Main Function"""
    logger.info('Got event %s', event)
    logger.info('Context %s', context)
    existing_cloudtrail_str = str(EXISTING_CLOUDTRAIL)
    existing_cloudtrail = existing_cloudtrail_str.lower()
    sensor_management_str = str(SENSOR_MANAGEMENT)
    sensor_management = sensor_management_str.lower()
    enable_ioa_str = str(ENABLE_IOA)
    enable_ioa = enable_ioa_str.lower()
    my_regions, comm_gov_eb_regions = get_active_regions()
    account = event['requestParameters']['accountId']
    ou = event['requestParameters']['destinationParentId']
    try:
        secrets = list(SECRET_LIST.split(","))
        for i in secrets:
            secret_str = get_secret(i, AWS_REGION)
            if secret_str:
                secrets_dict = json.loads(secret_str)
                falcon_client_id = secrets_dict['FalconClientId']
                falcon_secret = secrets_dict['FalconSecret']
                falcon_cloud = secrets_dict['FalconCloud']
                ou_list = secrets_dict['OUs']
                ous = list(ou_list.split(","))
                for i in ous:
                    if i in ou:
                        response = register_account(account, falcon_client_id, falcon_secret, falcon_cloud)
                        if response['status_code'] == 400:
                            error = response['body']['errors'][0]['message']
                            logger.info('Account %s Registration Failed with reason... %s', account, error)
                        elif response['status_code'] == 201:
                            logger.info('Account %s Registration Succeeded', account)
                            cs_account = response['body']['resources'][0]['intermediate_role_arn'].rsplit('::')[1]
                            cs_account_id = cs_account.rsplit(':')[0]
                            iam_role_name = response['body']['resources'][0]['iam_role_arn'].rsplit('/')[1]
                            cs_role_name = response['body']['resources'][0]['intermediate_role_arn'].rsplit('/')[1]
                            external_id = response['body']['resources'][0]['external_id']
                            logger.info(cs_account)
                            logger.info(cs_account_id)
                            if "gov" not in falcon_cloud:
                                cs_eventbus_name = response['body']['resources'][0]['eventbus_name']
                                if not EXISTING_CLOUDTRAIL:
                                    cs_bucket_name = response['body']['resources'][0]['aws_cloudtrail_bucket_name']
                                    add_stack_instance(account, iam_role_name, external_id, cs_role_name, cs_account_id, cs_bucket_name, cs_eventbus_name, falcon_client_id, falcon_secret, existing_cloudtrail, sensor_management, enable_ioa)
                                else:
                                    cs_bucket_name = 'none'
                                    add_stack_instance(account, iam_role_name, external_id, cs_role_name, cs_account_id, cs_bucket_name, cs_eventbus_name, falcon_client_id, falcon_secret, existing_cloudtrail, sensor_management, enable_ioa)

                            elif "gov" in falcon_cloud and AWS_ACCOUNT_TYPE == "govcloud" :
                                cs_eventbus_name = response['body']['resources'][0]['eventbus_name'].rsplit(',')[0]
                                if not EXISTING_CLOUDTRAIL:
                                    cs_bucket_name = response['body']['resources'][0]['aws_cloudtrail_bucket_name']
                                    gov_gov_stacksets(my_regions, account, iam_role_name, external_id, cs_role_name, cs_account_id, cs_bucket_name, cs_eventbus_name, falcon_client_id, falcon_secret, existing_cloudtrail, sensor_management, enable_ioa)
                                else:
                                    cs_bucket_name = 'none'
                                    gov_gov_stacksets(my_regions, account, iam_role_name, external_id, cs_role_name, cs_account_id, cs_bucket_name, cs_eventbus_name, falcon_client_id, falcon_secret, existing_cloudtrail, sensor_management, enable_ioa)

                            elif "gov" in falcon_cloud and AWS_ACCOUNT_TYPE == "commercial" :
                                if not EXISTING_CLOUDTRAIL:
                                    cs_bucket_name = response['body']['resources'][0]['aws_cloudtrail_bucket_name']
                                    comm_gov_stacksets(account, iam_role_name, external_id, cs_role_name, cs_account_id, cs_bucket_name, falcon_client_id, falcon_secret, existing_cloudtrail, sensor_management, comm_gov_eb_regions)
                                else:
                                    cs_bucket_name = 'none'
                                    comm_gov_stacksets(account, iam_role_name, external_id, cs_role_name, cs_account_id, cs_bucket_name, falcon_client_id, falcon_secret, existing_cloudtrail, sensor_management, comm_gov_eb_regions)
    except Exception as error:
        logger.info('Registration Failed %s', error)
