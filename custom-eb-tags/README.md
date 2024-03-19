![](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png)

## How to apply Custom Tags to EventBridge Rules

Cloudformation cannot natively apply tags to EventBridge Rules upon creation.  This solution provides a workaround for customers who need tags applied to all resources per AWS Organization SCPs or other requirements.

## How to Use

 1. Update tags in **crowdstrike_eb_rules.yml** (lines 82-83)
 2. Upload **crowdstrike_eb_rules.yml** and **crowdstrike_eb_rules.zip** to your S3 Bucket
 3. In **init_crowdstrike_aws_cspm_register.yml**, delete resources: `StackSetExecutionRole`, `StackSetAdministrationRole`, `CrowdStrikeEbStackSet` and `CrowdStrikeRootEbStackSet`
 2. Now add the code from **add_to_root.yml** to **init_crowdstrike_aws_cspm_register.yml**
 5. Update stack in in cloudformation with new template and upload your latest **init_crowdstrike_aws_cspm_register.yml**

## How it Works

Instead of using CloudFormation resources to create the EventBridge rules required by CrowdStrike Cloud Security IOAs, the stack instead creates a lambda function to create the EventBridge Rules, Targets and Tags using Python's Boto3.  The lambda function can accept any number of tags as long as they are provided in the environment variables of the resource in **crowdstrike_eb_rules.yml**.  When adding tags to the environment variables, use format `tag_<tag_key>: <tag_value>` as the Lambda will only create tags from variables with 'tag_' prefix.  The prefix `tag_` will be stripped from your tag key upon creation.  You may change/add tags and **Update** stack to apply new tags to EB Rules.

## Questions or concerns?

If you encounter any issues or have questions about this repository, please open an [issue](https://github.com/CrowdStrike/cloud-aws-registration-cloudformation/issues/new/choose).

## Statement of Support

CrowdStrike AWS Registration is a community-driven, open source project designed to provide options for onboarding AWS with CrowdStrike Cloud Security. While not a formal CrowdStrike product, this repo is maintained by CrowdStrike and supported in partnership with the open source community.
