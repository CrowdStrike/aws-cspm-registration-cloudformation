# Provision CrowdStrike Cloud Security with AWS Organizations

### Use this version if you have already registered the Organization via API and have access to the API response.  
### This can be useful if you are unable to deploy the registration lambda in this repo to your AWS Management account.

## Prerequisites

### Create Falcon API Client and Secret
1. In CrowdStrike Console, Navigate to API Clients and Keys page.
2. Click on "Add new API client".
3. Within the "Add new API client" modal, create a new client name and click on the Read and Write checkboxes next to CSPM registration under API Scopes.
4. Add new API Client
5. Save the CLIENT ID and SECRET displayed for your records. The SECRET will not be visible after this step.

### Register AWS Org with CrowdStrike Cloud Security service
Register your AWS Organization with  
`POST ​/cloud-connect-cspm-aws​/entities​/account​/v1`  
See [CrowdStrike API Docs](https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis) for details.

### Retrieve Required Attributes from API Response
- iam_role_arn
- intermediate_role_arn
- external_id
- eventbus_name

## Setup
1. Download the contents of this repository.
2. Log in to the Management Account of your AWS Organization
3. Upload the following files to the root of an S3 Bucket.
- crowdstrike_aws_cspm.json (Commercial AWS Only)
- crowdstrike_aws_gov_cspm.json (GovCloud AWS Only)
4. In the CloudFormation console select create stack.
5. Choose Specify Template and upload init_crowdstrike_aws_cspm_provision.yml
6. Fill out the parameters, click next.
7. Optional: change Stack Failure Options to Preserve successfully provisioned resources. This option will allow you to maintain the stack and update parameters in the event of a mistake.
8. Enabled the capabilities in the blue box and click submit.

## Parameter Details
| Parameter | Description | Options |
|---|---|---|
|AWSAccountType| Type of AWS Account |commercial or govcloud|
|FalconClientID| Falcon API client Id | |
|FalconSecret| Falcon API client secret| |
|PermissionsBoundary| Optional: Name of the Permissions Boundary Policy to apply to IAM Roles||
|EnableIOA| Whether to enable IOA| true, false|
|Regions| Which regions to deploy IOA resources| eg. us-east-1, us-east-2|
|ProvisionOU| Which OUs to deploy all CSPM resources. root OU to provision entire org or commademlimited list of child OUs| r-**** or ou-\*\*\*\*-\*\*\*\*, ou-\*\*\*\*-\*\*\*\* etc|
|EnableSensorManagement| Whether to enable Sensor Management| true, false|
|StackSetAdminRole| Name of new StackSet Admin role for root account stackset||
|StackSetExecRole| Name of new StackSet Execution role for root account stackset||
|CSRoleName|role name in intermediate_role_arn from API response||
|ExternalID|external_id from API response||
|ReaderRoleName|role name in iam_role_arn from API response||
|CSAccountNumber|account Id in intermediate_role_arn from API response||
|CSEventBusName|eventbus_name from API response||

## How it works
This template works the same as [init_crowdstrike_aws_cspm_register.yml](../README.md) but does not deploy a Lambda function to register the org.