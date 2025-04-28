from datetime import datetime
from flask import Flask, render_template, request
from aws_scan import (
    check_public_s3,
    check_open_security_groups,
    check_iam_admins,
    check_unused_ebs_volumes,
    check_high_duration_lambdas,
    check_high_cpu_ec2,
    check_high_storage_rds,
    check_s3_versioning,
    check_unused_iam_roles,
    check_iam_mfa,
    check_inactive_iam_users,
    check_old_access_keys,
    check_unencrypted_ebs_volumes,
    check_unencrypted_s3_buckets,
    check_underutilized_ec2,
    check_lambda_throttling_or_errors,
    get_account_id_and_username
)

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        access = request.form['access_key']
        secret = request.form['secret_key']
        region = request.form['region']

        try:
            # Fetch account ID and username
            account_id, username = get_account_id_and_username(access, secret, region)

            # Running checks
            s3 = check_public_s3(access, secret, region)
            sg = check_open_security_groups(access, secret, region)
            iam = check_iam_admins(access, secret, region)
            ebs = check_unused_ebs_volumes(access, secret, region)
            lambdas = check_high_duration_lambdas(access, secret, region)
            cpu = check_high_cpu_ec2(access, secret, region)
            rds = check_high_storage_rds(access, secret, region)
            s3_versioning = check_s3_versioning(access, secret, region)
            iam_roles = check_unused_iam_roles(access, secret, region)
            mfa = check_iam_mfa(access, secret, region)

            # New checks
            inactive_users = check_inactive_iam_users(access, secret, region)
            old_keys = check_old_access_keys(access, secret, region)
            unencrypted_ebs = check_unencrypted_ebs_volumes(access, secret, region)
            unencrypted_s3 = check_unencrypted_s3_buckets(access, secret, region)
            underutilized_ec2 = check_underutilized_ec2(access, secret, region)
            lambda_errors = check_lambda_throttling_or_errors(access, secret, region)

            # Calculate risk score and details
            risk_score, risk_details = calculate_risk_score(
                s3, sg, iam, ebs, lambdas, cpu, rds, s3_versioning, iam_roles, mfa, 
                inactive_users, old_keys, unencrypted_ebs, unencrypted_s3, underutilized_ec2, lambda_errors
            )

            # Determine risk category based on score
            if risk_score <= 30:
                risk_category = "Good"
            elif risk_score <= 70:
                risk_category = "Medium"
            else:
                risk_category = "High"

            return render_template("results.html", 
                                   s3=s3, sg=sg, iam=iam, ebs=ebs, lambdas=lambdas, cpu=cpu, rds=rds,
                                   s3_versioning=s3_versioning, iam_roles=iam_roles, mfa=mfa, 
                                   inactive_users=inactive_users, old_keys=old_keys, 
                                   unencrypted_ebs=unencrypted_ebs, unencrypted_s3=unencrypted_s3,
                                   underutilized_ec2=underutilized_ec2, lambda_errors=lambda_errors,
                                   risk_score=risk_score, risk_category=risk_category,
                                   risk_details=risk_details, 
                                   account_id=account_id, username=username,
                                   scantime=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        except Exception as e:
            return render_template("index.html", error=str(e))

    return render_template("index.html")

def calculate_risk_score(*args):
    # Assign weights for each check
    check_weights = {
        's3': 10,  # High risk: public S3
        'sg': 8,   # High risk: open security groups
        'iam': 5,  # Medium risk: IAM admins
        'ebs': 3,  # Medium risk: unused EBS volumes
        'lambdas': 6,  # Medium risk: high duration lambdas
        'cpu': 7,  # Medium risk: high CPU EC2
        'rds': 5,  # Medium risk: high storage RDS
        's3_versioning': 4,  # Low risk: non-versioned S3 buckets
        'iam_roles': 3,  # Low risk: unused IAM roles
        'mfa': 2,  # Low risk: IAM users without MFA
        'inactive_users': 6,  # Medium risk: inactive IAM users
        'old_keys': 5,  # Medium risk: old access keys
        'unencrypted_ebs': 7,  # High risk: unencrypted EBS volumes
        'unencrypted_s3': 7,  # High risk: unencrypted S3 buckets
        'underutilized_ec2': 4,  # Low risk: underutilized EC2 instances
        'lambda_errors': 6,  # Medium risk: lambda throttling or errors
    }

    # Calculate the total score based on the findings
    total_score = 0
    risk_details = {}
    
    checks = [
        ('s3', args[0]), ('sg', args[1]), ('iam', args[2]), ('ebs', args[3]),
        ('lambdas', args[4]), ('cpu', args[5]), ('rds', args[6]), ('s3_versioning', args[7]),
        ('iam_roles', args[8]), ('mfa', args[9]), ('inactive_users', args[10]), 
        ('old_keys', args[11]), ('unencrypted_ebs', args[12]), ('unencrypted_s3', args[13]),
        ('underutilized_ec2', args[14]), ('lambda_errors', args[15])
    ]
    
    for check, findings in checks:
        weight = check_weights[check]
        findings_count = len(findings)
        risk_details[check] = {
            'findings': findings,
            'weight': weight,
            'finding_count': findings_count,
            'total_risk': findings_count * weight
        }
        total_score += findings_count * weight
    
    max_score = 100
    total_score = min(total_score, max_score)
    
    return total_score, risk_details

if __name__ == "__main__":
    app.run(debug=True)
