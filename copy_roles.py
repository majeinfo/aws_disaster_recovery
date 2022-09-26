'''
Example of use:
$ ./copy_roles.py --src-profil SRC --dst-profil DST --role name -v
'''
import logging
import json
from copy_policies import get_policies

MAX_RESULTS = 200
SRC_TAG = 'SourceId'

logger = logging.getLogger('commands')


def copy_roles(src_client, dst_client, role_name=None, recreate=False):
    src_roles = get_roles(src_client)
    dst_roles = get_roles(dst_client)
    dst_policies = get_policies(dst_client)

    for role in src_roles:
        if role_name is None or role_name == role['RoleName']:
            copy_role(role, src_client, dst_roles, dst_policies, dst_client, recreate)


def get_roles(client):
    roles = []
    next_token = None

    while True:
        if next_token is None:
            role_slice = client.list_roles(MaxItems=MAX_RESULTS)
        else:
            role_slice = client.list_roles(Marker=next_token, MaxItems=MAX_RESULTS)

        roles += role_slice['Roles']

        if 'Marker' in role_slice:
            logger.info("MaxResults is too low for list_roles, go on with next_token...")
            next_token = role_slice['Marker']
        else:
            break

    return roles


def copy_role(role, src_client, dst_roles, dst_policies, dst_client, recreate=False):
    logger.debug(f"Copy role {role['RoleName']}")

    # Copy the role in the dst_client but destroy the existing one if needed
    for dst_role in dst_roles:
        if dst_role['RoleName'] == role['RoleName']:
            if recreate:
                logger.info(f"Role {role['RoleName']} already exists in destination Account, we recreate it !")
                # We must detach the Polcies first :
                policy_paginator = dst_client.get_paginator('list_attached_role_policies')
                for response in policy_paginator.paginate(RoleName=role['RoleName']):
                    for dst_policy in response['AttachedPolicies']:
                        response = dst_client.detach_role_policy(
                            RoleName=role['RoleName'],
                            PolicyArn=dst_policy['PolicyArn']
                        )
                dst_client.delete_role(RoleName=role['RoleName'])
            else:
                logger.error(f"Role {role['RoleName']} already exists in destination Account - use '--recreate'")
                return

    response = dst_client.create_role(
        Path=role['Path'],
        RoleName=role['RoleName'],
        AssumeRolePolicyDocument=json.dumps(role['AssumeRolePolicyDocument']),
        Description=role['Description'] if 'Description' in role else '',
        MaxSessionDuration=role['MaxSessionDuration'],
        #PermissionsBoundary=role['PermissionsBoundary'] if 'PermissionBoundary' in role else None,
        Tags=role['Tags'] if 'Tags' in role else [],
    )

    policy_paginator = src_client.get_paginator('list_attached_role_policies')
    for response in policy_paginator.paginate(RoleName=role['RoleName']):
        for policy in response['AttachedPolicies']:
            # Find the matching ARN in the dst account
            policy_arn = None
            for dst_policy in dst_policies:
                if dst_policy['PolicyName'] == policy['PolicyName']:
                    policy_arn = dst_policy['Arn']

            if policy_arn is None:
                logger.error(f"Policy {policy['PolicyName']} not found in destination Account")
                continue

            response = dst_client.attach_role_policy(
                RoleName=role['RoleName'],
                PolicyArn=policy_arn,
            )


if __name__ == '__main__':
    # standalone & batch mode
    import argparse
    import boto3

    usage = "%(prog)s --src-profile name --dst-profile name [--role name] [-v|--verbose] [-r|--recreate]"

    parser = argparse.ArgumentParser(
        description="Copy IAM Objects from a source account to a destination account",
        usage=usage
    )
    parser.add_argument("--src-profile", nargs='?', help="Name of source profile in .aws/config", required=True)
    parser.add_argument("--dst-profile", nargs='?', help="Name of destination profile in .aws/config or .aws/credentials", required=True)
    parser.add_argument("--role", nargs='?', help="Name of Role to copy (All by default)", default=None)
    parser.add_argument("-r", "--recreate", action="store_true", help="Recreate the Security Groups if they already exist in the destination", default=False)
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug mode", default=False)
    opts = parser.parse_args()

    if opts.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.addHandler(logging.StreamHandler())

    src_session = boto3.Session(profile_name=opts.src_profile)
    src_client =  src_session.client('iam')

    dst_session = boto3.Session(profile_name=opts.dst_profile)
    dst_client =  dst_session.client('iam')

    copy_roles(src_client, dst_client, opts.role, opts.recreate)


