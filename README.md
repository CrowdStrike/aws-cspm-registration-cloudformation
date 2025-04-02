> [!IMPORTANT]
> This repo is being deprecated!  
> Please see the Falcon Console for the latest Cloudformation Templates for AWS CSPM Onboarding.  
> This repo may still be used for Multiple CID scenarios.  

![](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png)

## CrowdStrike AWS Registration with CloudFormation

This repository provides CloudFormation templates to onboard AWS Organizations with CrowdStrike Cloud Security.

## Prerequisites

### Create Falcon API Client and Secret
1. In CrowdStrike Console, Navigate to API Clients and Keys page.
2. Click on "Add new API client".
3. Within the "Add new API client" modal, create a new client name and click on the Read and Write checkboxes next to CSPM registration under API Scopes..
4. Add new API Client
5. Save the CLIENT ID and SECRET displayed for your records. The SECRET will not be visible after this step.

### Ensure the Organization is not currently registered
1. In CrowdStrike Console, Navigate to Cloud Accounts Registration page.
2. Verify the AWS Organization and child accounts are not listed.
3. If they are listed, deregister and remove CrowdStrike resources from those accounts before proceeding.

### If the Organization is currently registered, or you do not want to run the Registration Lambda in the Management Account for any reason, see [Provision Only Steps](./provision-only/README.md)

## Setup
1. Download the contents of this repository.
2. Log in to the Management Account of your AWS Organization
3. Upload the following files to the root of an S3 Bucket.
- crowdstrike_aws_cspm_register_lambda.zip 
- crowdstrike_aws_cspm.json (Commercial AWS Only)
- crowdstrike_aws_gov_cspm.json (GovCloud AWS Only)
4. In the CloudFormation console select create stack.
5. Choose Specify Template and upload init_crowdstrike_aws_cspm_register.yml
6. Fill out the parameters, click next.
7. Optional: change Stack Failure Options to Preserve successfully provisioned resources. This option will allow you to maintain the stack and update parameters in the event of a mistake.
7. Enabled the capabilities in the blue box and click submit.

## Parameter Details
| Parameter | Description | Options |
|---|---|---|
|FalconAccountType| Type of CrowdStrike Falcon Account |commercial or govcloud|
|AWSAccountType| Type of AWS Account |commercial or govcloud|
|S3Bucket| Name of the S3 Bucket containing lambda.zip| |
|PermissionsBoundary| Optional: Name of the Permissions Boundary Policy to apply to IAM Roles||
|FalconClientID| Falcon API client Id | |
|FalconSecret| Falcon API client secret| |
|CSCloud| Falcon Cloud region| us1, us2, eu1, usgov1, usgov2|
|EnableIOA| Whether to enable IOA| true, false|
|Regions| Which regions to deploy IOA resources| eg. us-east-1, us-east-2|
|ProvisionOU| Which OUs to deploy all CSPM resources. root OU to provision entire org or commademlimited list of child OUs| r-**** or ou-\*\*\*\*-\*\*\*\*, ou-\*\*\*\*-\*\*\*\* etc|
|EnableSensorManagement| Whether to enable Sensor Management| true, false|
|StackSetAdminRole| Name of new StackSet Admin role for root account stackset||
|StackSetExecRole| Name of new StackSet Execution role for root account stackset||

## How It Works

- Root CloudFormation Stack 
1. Create Secret to manage Falcon API Credentials
2. Create Lambda to register AWS Org with Falcon Cloud Security Service via API
3. Create Child Stacks and StackSets to provision root account and child accounts with CrowdStrike Cloud Security resources
- Root CrowdStrikeStack
1. Create Stacks in root account using [IOM template](./crowdstrike_aws_cspm.json)
2. Create CSPM Reader Role for IOMs
3. Create IOA Role for Eventbridge (if EnableIOA = true)
4. Create Sensor Management Role and Lambda (if EnableSensorManagement = true)
- CrowdStrike-Cloud-Security-Stackset 
1. Create Stacks in each child account using [IOM template](./crowdstrike_aws_cspm.json)
2. Create CSPM Reader Role for IOMs
3. Create IOA Role for Eventbridge (if EnableIOA = true)
4. Create Sensor Management Role and Lambda (if EnableSensorManagement = true)
- CrowdStrike-Cloud-Security-EB-Stackset 
1. Create Stacks in each child account using [IOA template](https://cs-prod-cloudconnect-templates.s3.amazonaws.com/aws_cspm_cloudformation_eb_v2.json)
2. Create EventBridge rules to forward IOAs
- CrowdStrike-Cloud-Security-Root-EB-Stackset
1. Create Stacks in root account using [IOA template](https://cs-prod-cloudconnect-templates.s3.amazonaws.com/aws_cspm_cloudformation_eb_v2.json)
2. Create EventBridge rules to forward IOAs

**Note**: If provisioning govcloud, the following templates are used instead:
- [GovCloud IOM template](./crowdstrike_aws_gov_cspm.json)
- [GovCloud IOA template](https://cs-csgov-laggar-cloudconnect-templates.s3-us-gov-west-1.amazonaws.com/aws_cspm_cloudformation_eb_v2.json)

## Questions or concerns?

If you encounter any issues or have questions about this repository, please open an [issue](https://github.com/CrowdStrike/cloud-aws-registration-cloudformation/issues/new/choose).

## Statement of Support

CrowdStrike AWS Registration is a community-driven, open source project designed to provide options for onboarding AWS with CrowdStrike Cloud Security. While not a formal CrowdStrike product, this repo is maintained by CrowdStrike and supported in partnership with the open source community.