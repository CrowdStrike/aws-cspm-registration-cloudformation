import json
import logging
import os
import ast
import boto3
import requests
import botocore


logger = logging.getLogger()
logger.setLevel(logging.INFO)

# CONSTANTS
SUCCESS = "SUCCESS"
FAILED = "FAILED"
AWS_REGION = os.environ['aws_region']
EB_REGIONS = os.environ['eb_regions']
DEFAULT_REGION = 'us-east-1'
CS_EVENT_BUS = os.environ['eventbus_name']
CS_ACCOUNT_ID = os.environ['cs_account_id']
IOA_RULE_NAME = 'cs-cloudtrail-events-ioa-rule'
RO_RULE_NAME = 'cs-cloudtrail-events-readonly-rule'

class tags:
    def __init__(self, Key, Value):
        self.Key = Key
        self.Value = Value

def generate_tags():
    list = []

    for name, value in os.environ.items():
        if "tag_" in name:
            key = name.replace('tag_', '')
            list.append(tags(key, value))

    json_tags_string = json.dumps([obj.__dict__ for obj in list])
    json_tags = ast.literal_eval(json_tags_string)
    return json_tags

def put_rules(aws_account_id, json_tags):
    session = boto3.session.Session()
    regions = EB_REGIONS.split(',')
    for region in regions:
        client = session.client(
            service_name='events',
            region_name=region
        )
        try:
            response1 = client.put_rule(
                Name=IOA_RULE_NAME,
                EventPattern= """
                {
                    "detail-type": [{
                        "suffix": "via CloudTrail"
                    }],
                    "source": [{
                        "prefix": "aws."
                    }],
                    "detail": {
                        "eventName": [{
                        "anything-but": ["InvokeExecution", "Invoke", "UploadPart"]
                        }],
                        "readOnly": [false]
                    }
                }
                """,
                State='ENABLED',
                Tags=json_tags
            )
            print(response1)
            response2 = client.put_targets(
                Rule=IOA_RULE_NAME,
                Targets=[
                    {
                        'Id': 'CrowdStrikeCentralizeEvents',
                        'Arn': f'arn:aws:events:{DEFAULT_REGION}:{CS_ACCOUNT_ID}:event-bus/{CS_EVENT_BUS}',
                        'RoleArn': f'arn:aws:iam::{aws_account_id}:role/CrowdStrikeCSPMEventBridge'
                    },
                ]
            )
            print(response2)
            response3 = client.put_rule(
                Name=RO_RULE_NAME,
                EventPattern= """
                {
                    "$or": [{
                        "detail": {
                        "eventName": [{
                            "anything-but": ["GetObject", "Encrypt", "Decrypt", "HeadObject", "ListObjects", "GenerateDataKey", "Sign", "AssumeRole"]
                        }]
                        }
                    }, {
                        "detail": {
                        "eventName": ["AssumeRole"],
                        "userIdentity": {
                            "type": [{
                            "anything-but": ["AWSService"]
                            }]
                        }
                        }
                    }],
                    "detail-type": [{
                        "suffix": "via CloudTrail"
                    }],
                    "source": [{
                        "prefix": "aws."
                    }],
                    "detail": {
                        "readOnly": [true]
                    }
                }
                """,
                State='ENABLED',
                Tags=json_tags
            )
            print(response3)
            response4 = client.put_targets(
                Rule=RO_RULE_NAME,
                Targets=[
                    {
                        'Id': 'CrowdStrikeCentralizeEvents',
                        'Arn': f'arn:aws:events:{DEFAULT_REGION}:{CS_ACCOUNT_ID}:event-bus/{CS_EVENT_BUS}',
                        'RoleArn': f'arn:aws:iam::{aws_account_id}:role/CrowdStrikeCSPMEventBridge'
                    },
                ]
            )
            print(response4)
        except botocore.exceptions.ClientError as error:
            logger.error(error)
    return

def delete_rules():
    session = boto3.session.Session()
    regions = EB_REGIONS.split(',')
    for region in regions:
        client = session.client(
            service_name='events',
            region_name=region)
        try:
            client.remove_targets(
                Rule=IOA_RULE_NAME,
                Ids=[
                    'CrowdStrikeCentralizeEvents',
                ],
                Force=True
            )
            client.remove_targets(
                Rule=RO_RULE_NAME,
                Ids=[
                    'CrowdStrikeCentralizeEvents',
                ],
                Force=True
            )
            client.delete_rule(
                Name=IOA_RULE_NAME
            )
            client.delete_rule(
                Name=RO_RULE_NAME
            )
        except botocore.exceptions.ClientError as error:
            logger.error(error)
    return
    
def cfnresponse_send(event, responseStatus, responseData, noEcho=False):
    responseUrl = event['ResponseURL']
    print(responseUrl)
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: '
    responseBody['PhysicalResourceId'] = 'CustomResourcePhysicalID'
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['Data'] = responseData
    json_responseBody = json.dumps(responseBody)
    print("Response body:\n" + json_responseBody)
    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }
    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))

def lambda_handler(event, context):
    logger.info('Got event {}'.format(event))
    logger.info('Context {}'.format(context))
    aws_account_id = context.invoked_function_arn.split(":")[4]
    json_tags = generate_tags()
    json_tags
    try:
            if event['RequestType'] in ['Create']:
                logger.info('Event = {}'.format(event))
                put_rules(aws_account_id, json_tags)
                response_data = {}
                response_data['result'] = "EB Rules Created: {}, {}".format(IOA_RULE_NAME, RO_RULE_NAME)
                cfnresponse_send(event, SUCCESS, response_data)
            elif event['RequestType'] in ['Update']:
                logger.info('Event = {}'.format(event))
                delete_rules()
                put_rules(aws_account_id, json_tags)
                response_data = {}
                response_data['result'] = "EB Rules Created: {}, {}".format(IOA_RULE_NAME, RO_RULE_NAME)
                cfnresponse_send(event, SUCCESS, response_data)
            elif event['RequestType'] in ['Delete']:
                logger.info('Event = ' + event['RequestType'])
                delete_rules()
                response_data = {}
                response_data['result'] = "EB Rules Deleted: {}, {}".format(IOA_RULE_NAME, RO_RULE_NAME)
                cfnresponse_send(event, SUCCESS, response_data)
    except Exception as err:
        error = 'EB Creation Failed {}'.format(err)
        logger.info(error)
        response_data = {}
        response_data['error'] = error
        cfnresponse_send(event, FAILED, response_data)