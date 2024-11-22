"""Cleanup CrowdStrike Multi-CID Deployment"""
import time
import boto3

CONTEXT = 'SELF' # 'SELF'|'DELEGATED_ADMIN'

def get_region():
    """Get current AWS Region"""
    session = boto3.session.Session()
    current_region = session.region_name
    return current_region

def get_stacksets(current_region):
    """Get list of CrowdStrike-Cloud-Security StackSet names"""
    session = boto3.session.Session()
    client = session.client(
        service_name='cloudformation',
        region_name=current_region
    )
    stacksets = []
    stacksets_response = client.list_stack_sets(
        MaxResults=100,
        Status='ACTIVE',
        CallAs=CONTEXT
    )
    summaries = stacksets_response['Summaries']
    print('\nThe following StackSets will be destroyed:')
    for i in summaries:
        if 'CrowdStrike-Cloud-Security' in i['StackSetName']:
            print(i['StackSetName'])
            stacksets += [i['StackSetName']]
    return stacksets

def delete_stack_instances(current_region, stacksets):
    """Delete Stack Instances from CrowdStrike-Cloud-Security StackSets"""
    session = boto3.session.Session()
    client = session.client(
        service_name='cloudformation',
        region_name=current_region
    )
    for stackset in stacksets:
        regions = []
        num = 12; length = len(stackset)
        account_id = stackset[length - num:]
        if account_id.isdigit():
            print(f'proccessing account id: {account_id}')
            instances = client.list_stack_instances(
                StackSetName=stackset,
                CallAs=CONTEXT
            )
            summaries = instances['Summaries']
            for i in summaries:
                regions += [i['Region']]
            for region in regions:
                response = client.delete_stack_instances(
                    StackSetName=stackset,
                    Accounts=[
                        account_id,
                    ],
                    Regions=[
                        region,
                    ],
                    RetainStacks=False,
                    CallAs=CONTEXT
                )
                print(response)

def delete_stacksets(current_region, stacksets):
    """Delete CrowdStrike-Cloud-Security StackSets"""
    session = boto3.session.Session()
    client = session.client(
        service_name='cloudformation',
        region_name=current_region
    )
    for stackset in stacksets:
        num = 12
        length = len(stackset)
        account_id = stackset[length - num:]
        if account_id.isdigit():
            print(f'deleting {stackset}')
            response = client.delete_stack_set(
                StackSetName=stackset,
                CallAs=CONTEXT
            )
            print(response)

current_region = get_region()
stacksets = get_stacksets(current_region)
response = input("\nType 'yes' to continue\n")
if 'yes' in response:
  delete_stack_instances(current_region, stacksets)
  print('waiting...')
  time.sleep(180)
  delete_stacksets(current_region, stacksets)
