# AWS Account Analyzer

The **AWS Account Analyzer** is a web application that performs an in-depth analysis of your AWS account. It checks for security vulnerabilities, performance inefficiencies, and cost optimization opportunities in your AWS environment. The app utilizes AWS services such as EC2, S3, IAM, Lambda, RDS, and more to perform a comprehensive risk scan.

The app provides a detailed report with a **risk score** and actionable insights. It is built using **Flask** for the backend, **TailwindCSS** for the frontend, and **boto3** for interacting with AWS services.

## Features

### Security Checks
- **Public S3 Buckets**: Detects publicly accessible S3 buckets.
- **Open Security Groups**: Flags security groups allowing unrestricted inbound traffic.
- **IAM Admin Users**: Identifies IAM users with administrative privileges.
- **Unused EBS Volumes**: Detects unassociated EBS volumes.
- **High Duration Lambda Functions**: Flags Lambda functions that exceed specified execution time thresholds.
- **Unencrypted EBS Volumes**: Identifies unencrypted EBS volumes.
- **Unencrypted S3 Buckets**: Flags unencrypted S3 buckets.
- **IAM Users without MFA**: Flags IAM users without multi-factor authentication (MFA) enabled.
- **Inactive IAM Users**: Detects IAM users who haven't logged in for a specified period.
- **Old Access Keys**: Identifies IAM users with access keys older than a specified time.
- **Unused IAM Roles**: Identifies IAM roles that are not associated with any active resources.
- **S3 Versioning**: Checks whether S3 buckets have versioning enabled.

### Performance Checks
- **Underutilized EC2 Instances**: Detects EC2 instances that are underutilized based on CPU usage.
- **High CPU EC2 Instances**: Flags EC2 instances with high CPU usage.
- **High Storage RDS Instances**: Flags RDS instances with low free storage.
- **Lambda Throttling/Errors**: Detects Lambda functions experiencing throttling or errors.

### Cost Optimization
- **Unused Resources**: Identifies unused resources such as EC2 instances and EBS volumes that might incur unnecessary costs.
- **Right-Sizing Recommendations**: Provides recommendations for optimizing EC2 instances and RDS configurations based on usage.

### Risk Scoring
The app calculates a **risk score** based on the severity of the findings. Each issue found is assigned a weight and combined to generate an overall risk score, which is displayed on the dashboard. The risk score is categorized into three levels:
- **Low Risk**
- **Medium Risk**
- **High Risk**

## Technologies Used

- **Flask**: Backend web framework for handling HTTP requests.
- **TailwindCSS**: Utility-first CSS framework for styling the frontend.
- **boto3**: AWS SDK for Python, used to interact with AWS services (EC2, S3, IAM, Lambda, RDS, etc.).
- **Jinja2**: Templating engine used by Flask for dynamic page rendering.
- **SQLite**: Used for storing scan metadata locally (you can switch to DynamoDB for production).

## Prerequisites

Before running the app, ensure you have the following:

- Python 3.x
- AWS credentials (access key and secret key) configured in the environment.
- Install AWS CLI and configure your credentials (`aws configure`).
- An active AWS account with permissions to access resources.
