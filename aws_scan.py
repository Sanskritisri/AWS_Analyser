import boto3
from datetime import datetime, timedelta, timezone


def get_client(service, access, secret, region):
    return boto3.client(
        service,
        aws_access_key_id=access,
        aws_secret_access_key=secret,
        region_name=region
    )

def get_account_id_and_username(access, secret, region):
    sts_client = get_client('sts', access, secret, region)
    iam_client = get_client('iam', access, secret, region)

    account_id = sts_client.get_caller_identity()['Account']
    # Get current username (assuming user credentials are used)
    current_user = iam_client.get_user()['User']['UserName']
    
    return account_id, current_user



def check_public_s3(access, secret, region):
    s3 = get_client('s3', access, secret, region)
    buckets = s3.list_buckets()['Buckets']
    public_buckets = []

    for bucket in buckets:
        try:
            acl = s3.get_bucket_acl(Bucket=bucket['Name'])
            for grant in acl['Grants']:
                if 'AllUsers' in str(grant['Grantee']):
                    public_buckets.append(bucket['Name'])
        except:
            pass
    return public_buckets

def check_open_security_groups(access, secret, region):
    ec2 = get_client('ec2', access, secret, region)
    sgs = ec2.describe_security_groups()['SecurityGroups']
    open_sgs = []

    for sg in sgs:
        for perm in sg['IpPermissions']:
            for ip_range in perm.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    open_sgs.append({'GroupId': sg['GroupId'], 'Port': perm.get('FromPort', 'ALL')})
    return open_sgs

def check_iam_admins(access, secret, region):
    iam = get_client('iam', access, secret, region)
    users = iam.list_users()['Users']
    admins = []

    for user in users:
        policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
        for policy in policies:
            if policy['PolicyName'] == 'AdministratorAccess':
                admins.append(user['UserName'])
    return admins

def check_unused_ebs_volumes(access, secret, region):
    ec2 = get_client('ec2', access, secret, region)
    volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])['Volumes']
    return [{'VolumeId': v['VolumeId'], 'Size': v['Size']} for v in volumes]

def check_high_duration_lambdas(access, secret, region):
    lambda_client = get_client('lambda', access, secret, region)
    functions = lambda_client.list_functions()['Functions']
    return [
        {'FunctionName': f['FunctionName'], 'Timeout': f['Timeout']}
        for f in functions if f['Timeout'] > 10
    ]

def check_high_cpu_ec2(access, secret, region):
    ec2 = get_client('ec2', access, secret, region)
    cloudwatch = get_client('cloudwatch', access, secret, region)
    instances = ec2.describe_instances()['Reservations']
    high_cpu_instances = []

    for reservation in instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            stats = cloudwatch.get_metric_statistics(
                Period=3600,
                StartTime='2025-04-01T00:00:00Z',
                EndTime='2025-04-07T23:59:59Z',
                MetricName='CPUUtilization',
                Namespace='AWS/EC2',
                Statistics=['Average'],
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}]
            )
            if stats['Datapoints']:
                avg_cpu = stats['Datapoints'][0]['Average']
                if avg_cpu > 80:  # Flag instances with > 80% CPU usage
                    high_cpu_instances.append(instance_id)
    return high_cpu_instances

def check_high_storage_rds(access, secret, region):
    rds = get_client('rds', access, secret, region)
    cloudwatch = get_client('cloudwatch', access, secret, region)
    rds_instances = rds.describe_db_instances()['DBInstances']
    high_storage_instances = []

    for instance in rds_instances:
        db_instance_id = instance['DBInstanceIdentifier']
        stats = cloudwatch.get_metric_statistics(
            Period=3600,
            StartTime='2025-04-01T00:00:00Z',
            EndTime='2025-04-07T23:59:59Z',
            MetricName='FreeStorageSpace',
            Namespace='AWS/RDS',
            Statistics=['Minimum'],
            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}]
        )
        if stats['Datapoints']:
            min_storage = stats['Datapoints'][0]['Minimum']
            if min_storage < 10 * 1024 * 1024 * 1024:  # < 10GB of free space
                high_storage_instances.append(db_instance_id)
    return high_storage_instances

def check_s3_versioning(access, secret, region):
    s3 = get_client('s3', access, secret, region)
    buckets = s3.list_buckets()['Buckets']
    non_versioned_buckets = []

    for bucket in buckets:
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket['Name'])
            if versioning.get('Status') != 'Enabled':
                non_versioned_buckets.append(bucket['Name'])
        except:
            pass
    return non_versioned_buckets

def check_unused_iam_roles(access, secret, region):
    iam = get_client('iam', access, secret, region)
    roles = iam.list_roles()['Roles']
    unused_roles = []

    for role in roles:
        attached_policies = iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
        if not attached_policies:
            unused_roles.append(role['RoleName'])
    
    return unused_roles

def check_iam_mfa(access, secret, region):
    iam = get_client('iam', access, secret, region)
    users = iam.list_users()['Users']
    users_without_mfa = []

    for user in users:
        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa_devices:
            users_without_mfa.append(user['UserName'])
    
    return users_without_mfa  

# New Security Check: Inactive IAM Users
def check_inactive_iam_users(access, secret, region):
    iam = get_client('iam', access, secret, region)
    users = iam.list_users()['Users']
    inactive_users = []
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)  # ✅ aware

    for user in users:
        last_used = iam.get_user(UserName=user['UserName']).get('User', {}).get('PasswordLastUsed')
        if last_used and last_used < cutoff_date:
            inactive_users.append(user['UserName'])

    return inactive_users

# New Security Check: Access Keys Not Rotated
def check_old_access_keys(access, secret, region):
    iam = get_client('iam', access, secret, region)
    users = iam.list_users()['Users']
    old_keys = []
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)  # ✅ aware

    for user in users:
        keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
        for key in keys:
            if key['CreateDate'] < cutoff_date:
                old_keys.append({'User': user['UserName'], 'AccessKey': key['AccessKeyId']})

    return old_keys

# New Security Check: Unencrypted EBS Volumes
def check_unencrypted_ebs_volumes(access, secret, region):
    ec2 = get_client('ec2', access, secret, region)
    volumes = ec2.describe_volumes()['Volumes']
    unencrypted_volumes = []

    for volume in volumes:
        if 'Encrypted' not in volume or not volume['Encrypted']:
            unencrypted_volumes.append(volume['VolumeId'])
    
    return unencrypted_volumes

# New Security Check: Unencrypted S3 Buckets
def check_unencrypted_s3_buckets(access, secret, region):
    s3 = get_client('s3', access, secret, region)
    buckets = s3.list_buckets()['Buckets']
    unencrypted_buckets = []

    for bucket in buckets:
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket['Name'])
            if 'ServerSideEncryptionConfiguration' not in encryption:
                unencrypted_buckets.append(bucket['Name'])
        except:
            unencrypted_buckets.append(bucket['Name'])
    
    return unencrypted_buckets

# New Cost Optimization Check: Underutilized EC2 Instances
def check_underutilized_ec2(access, secret, region):
    ec2 = get_client('ec2', access, secret, region)
    cloudwatch = get_client('cloudwatch', access, secret, region)
    instances = ec2.describe_instances()['Reservations']
    underutilized_instances = []

    for reservation in instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            stats = cloudwatch.get_metric_statistics(
                Period=3600,
                StartTime='2025-04-01T00:00:00Z',
                EndTime='2025-04-07T23:59:59Z',
                MetricName='CPUUtilization',
                Namespace='AWS/EC2',
                Statistics=['Average'],
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}]
            )
            if stats['Datapoints']:
                avg_cpu = stats['Datapoints'][0]['Average']
                if avg_cpu < 10:  # Flag instances with < 10% CPU usage
                    underutilized_instances.append(instance_id)
    return underutilized_instances

# New Performance Check: Lambda Throttling or Errors
def check_lambda_throttling_or_errors(access, secret, region):
    lambda_client = get_client('lambda', access, secret, region)
    cloudwatch = get_client('cloudwatch', access, secret, region)
    functions = lambda_client.list_functions()['Functions']
    problematic_functions = []

    for func in functions:
        function_name = func['FunctionName']
        for metric_name in ['Throttles', 'Errors']:
            stats = cloudwatch.get_metric_statistics(
                Period=3600,
                StartTime=datetime(2025, 4, 1, tzinfo=timezone.utc),
                EndTime=datetime(2025, 4, 7, 23, 59, 59, tzinfo=timezone.utc),
                MetricName=metric_name,
                Namespace='AWS/Lambda',
                Statistics=['Sum'],
                Dimensions=[{'Name': 'FunctionName', 'Value': function_name}]
            )
            if stats['Datapoints']:
                if stats['Datapoints'][0]['Sum'] > 0:
                    problematic_functions.append({
                        'FunctionName': function_name,
                        'Issue': metric_name
                    })
    return problematic_functions
# New Performance Check: Lambda Throttling or Errors
def check_lambda_throttling_or_errors(access, secret, region):
    lambda_client = get_client('lambda', access, secret, region)
    cloudwatch = get_client('cloudwatch', access, secret, region)
    functions = lambda_client.list_functions()['Functions']
    problematic_functions = []

    for func in functions:
        function_name = func['FunctionName']
        for metric_name in ['Throttles', 'Errors']:
            stats = cloudwatch.get_metric_statistics(
                Period=3600,
                StartTime=datetime(2025, 4, 1, tzinfo=timezone.utc),
                EndTime=datetime(2025, 4, 7, 23, 59, 59, tzinfo=timezone.utc),
                MetricName=metric_name,
                Namespace='AWS/Lambda',
                Statistics=['Sum'],
                Dimensions=[{'Name': 'FunctionName', 'Value': function_name}]
            )
            if stats['Datapoints']:
                if stats['Datapoints'][0]['Sum'] > 0:
                    problematic_functions.append({
                        'FunctionName': function_name,
                        'Issue': metric_name
                    })
    return problematic_functions


