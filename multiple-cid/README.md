![](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png)

## CrowdStrike AWS Registration with Multiple Falcon CIDs

This repository provides CloudFormation templates to onboard AWS Organizations with two CrowdStrike Falcon CIDs.

## Prerequisites

### Create Falcon API Client and Secret
1. In CrowdStrike Console, Navigate to API Clients and Keys page.
2. Click on "Add new API client".
3. Within the "Add new API client" modal, create a new client name and click on the Read and Write checkboxes next to **CSPM registration** and **Cloud security AWS registration** under API Scopes..
4. Add new API Client
5. Save the CLIENT ID and SECRET displayed for your records. The SECRET will not be visible after this step.

### Ensure the Organization is not currently registered
1. In CrowdStrike Console, Navigate to Cloud Accounts Registration page.
2. Verify the AWS Organization and child accounts are not listed.
3. If they are listed, deregister and remove CrowdStrike resources from those accounts before proceeding.


## Setup
1. Download the contents of this repository.
2. Log in to the Management Account of your AWS Organization.
3. Upload the following files to the root of an S3 Bucket.
- init_lambda_function.zip 
- new_accounts_lambda_function.zip
- init_crowdstrike_multiple_cid.yml
- crowdstrike_stackset_role_setup
- crowdstrike_aws_cspm.json (located in root of this repo)
- crowdstrike_aws_gov_cspm.json (located in root of this repo)
4. In the CloudFormation console select create stack.
5. Choose Specify Template and upload init_crowdstrike_multiple_cid.yml
6. Fill out the parameters, click next.
7. Optional: change Stack Failure Options to Preserve successfully provisioned resources. This option will allow you to maintain the stack and update parameters in the event of a mistake.
7. Enabled the capabilities in the blue box and click submit.

## Parameter Details
The Parameters in this template are divided into three sections.

### Multi-CID Configuration
This template provides parameters to create two AWS Secrets Manager Secrets, each to contain a different set of Falcon API credentials and the corresponding list of AWS OUs.  These secrets determine which AWS OUs are registered to which Falcon CID.
| Parameter | Description | Options |
|---|---|---|
|CIDA| Falcon CID for OUA, FalconClientIdA & FalconSecretA |string|
|OUA| List of OUs to register with CIDA |list of string|
|FalconClientIdA| Your CrowdStrike Falcon OAuth2 Client ID for CIDA |string|
|FalconSecretA| Your CrowdStrike Falcon OAuth2 API Secret for CIDA|string|
|CIDB| Falcon CID for OUB, FalconClientIdB & FalconSecretB |string|
|OUB| List of OUs to register with CIDB |list of string|
|FalconClientIdB| Your CrowdStrike Falcon OAuth2 Client ID for CIDB |string|
|FalconSecretB| Your CrowdStrike Falcon OAuth2 API Secret for CIDB|string|

### CSPM Configuration
This section provides the parameters necessary to configure your CSPM Registration.
| Parameter | Description | Options |
|---|---|---|
|EnableIOA| Whether to enable IOAs| true, false |
|UseExistingCloudTrail| Select False ONLY if you wish to create a new cloudtrail for Read-Only IOAs (this is not common) | true, false |
|EnableSensorManagement| Whether to enable 1Click | true, false|
|APICredentialsStorageMode| If EnableSensorManagement = true, whether to store falcon API credentials in Secrets Manager or as lambda environment variables.| secret, lambda|
|Regions| Which regions to enable IOA|string|

### Misc
This section provides additional parameters to complete the deployment of this solution.
| Parameter | Description | Options |
|---|---|---|
|S3Bucket| NAME of the S3 Bucket used in Step 3 of Setup| string |
|AWSAccountType| Whether this AWS Organization is commercial or GovCloud | commercial, govcloud |
|RootOU| the root OU (eg. r-****) of this AWS Organization | string|
|StackSetAdminRole| What to Name the Administration Role for CrowdStrike StackSets, this role will be created as a part of this stack | string|
|StackSetExecRole| What to Name the Execution Role for CrowdStrike StackSets, this role will be created as a part of this stack |string|

## Post Deployment Steps

### Initial Registration
1. Navigate to Lambda and open the crowdstrike-cloud-initial-registration function.
2. Create and save an empty test event. eg. {}
3. Click test.

This will execute the Lambda to retrieve your API Credentials from Secrets Manager and register each account to the CID mapped to its Parent OU.  Upon a successful registration, Lambda will trigger the StackSets required to onbaord the Account.

### New Account Registration
When an AWS Account is created AND moved under an OU, EventBridge will trigger the crowdstrike-cloud-new-registration function. This will execute the Lambda to retrieve your API Credentials from Secrets Manager and register the account to the CID mapped to its Parent OU.  Upon a successful registration, Lambda will trigger the StackSets required to onbaord the Account.

### Validate Registration
1. Each account will have a correspondiong stackset named CrowdStrike-Cloud-Security-Stackset-{accountID}.  You can open and review the status of stack instances to confirm the account has been onboarded.
2. Each account will appear in Falcon>Cloud Security>Cloud Accounts Registration.  Be sure to refresh the list to get the most up-to-date status of each account.

### Enable/Disable Services
This solution allows for services to be enabled or disabled after the initial deployment.

#### 1Click
If 1click was not enabled, ie. the parameter ```EnableSensorManagement``` was set to false, and you wish to enable after deployment of this solution:

**For existing Accounts:**
1. Navigate to CloudFormation StackSets and select the ```CrowdStrike-Cloud-Security-Stackset-{account-id}```.
2. Click **Actions** and click **Override StackSet Parameters**.
3. Add the Account ID and region and click next.
4. Select the ```EnableSensorManagement``` and click **Edit override value** and **Override StackSet Value**.
5. Change the value from ```false``` to ```true``` and **save changes**.
6. Click **Next** then **Submit**

This will update the stack within the target account to deploy 1Click resources.  Within a few minutes, 1Click should be **Active** in the Falcon Console.

**For all Accounts going forward:**
1. Navigate to Lambda and open the function ```crowdstrike-cloud-new-registration```.
2. Click on **Configuration** and **Environment Variables**.
3. Update the value on ```sensor_management``` from ```False``` to ```True```.
4. Save.
5. Repeat the above steps for the Lambda function ```crowdstrike-cloud-initial-registration```.

This will ensure all future account registrations will apply the stacksets with ```EnableSensorManagement``` set to ```true`` which will ensure the target account is onboarded with 1Click Resources.

The above steps are the same if you are instead **Disabling** 1Click after having deployed this solution with 1Click **Enabled**.  For each relevant step, instead change the value from ```True``` to ```False```.

### Troubleshooting
If an account either does not appear in Falcon or shows as inactive more than an hour after registration, review the logs for each Lambda function in cloudwatch logs and review the StackSet for that account to ensure no errors occured during stack deployment.

### Cleanup

If for any reason you must roll back this deployment, it is very important to first delete the StackSet instances and StackSets created by this approach:
- CrowdStrike-Cloud-Security-EB-Stackset-account_id
- CrowdStrike-Cloud-Security-IOA-Stackset-account_id
- CrowdStrike-Cloud-Security-Stackset-account_id

If you fail to do so before deleting the root CloudFormation Stack, these will become inoperable because they are 'Self-Managed' StackSets which rely on the IAM Roles deployed by the root stack to function.

A script has been included in this repo [cleanup.py](cleanup.py) to make this easier.  You may run this in your AWS CloudShell to remove the Stack Instances and StackSets before continuing to delete the root stack.

**Note:** cleanup.py will prompt you to validate the list of StackSets it will delete before continuing.  Please ensure you are 100% confident in the list of StackSets before continuing.

**Note:** After performing cleanup steps you must goto Falcon Cloud Accounts Registration to complete the cleanup process and "Deprovision" the accounts from Falcon.  This will complete the deregistration process.

## Questions or concerns?

If you encounter any issues or have questions about this repository, please open an [issue](https://github.com/CrowdStrike/cloud-aws-registration-cloudformation/issues/new/choose).

## Statement of Support

CrowdStrike AWS Registration is a community-driven, open source project designed to provide options for onboarding AWS with CrowdStrike Cloud Security. While not a formal CrowdStrike product, this repo is maintained by CrowdStrike and supported in partnership with the open source community.