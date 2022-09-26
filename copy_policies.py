'''
Example of use:
$ ./copy_policies.py --src-profil SRC --dst-profil DST --policy name -v
'''
import logging
import json

MAX_RESULTS = 200
SRC_TAG = 'SourceId'

logger = logging.getLogger('commands')


def copy_policies(src_client, dst_client, policy_name=None, recreate=False):
    src_policies = get_policies(src_client)
    dst_policies = get_policies(dst_client)

    for policy in src_policies:
        if policy_name is None or policy_name == policy['PolicyName']:
            copy_policy(policy, src_client, dst_policies, dst_client, recreate)


def get_policies(client):
    policies = []
    next_token = None

    while True:
        if next_token is None:
            pol_slice = client.list_policies(Scope='Local', OnlyAttached=False, MaxItems=MAX_RESULTS)
        else:
            pol_slice = client.list_policies(Scope='Local', OnlyAttached=False, Marker=next_token, MaxItems=MAX_RESULTS)

        policies += pol_slice['Policies']

        if 'Marker' in pol_slice:
            logger.info("MaxResults is too low for list_policies, go on with next_token...")
            next_token = pol_slice['Marker']
        else:
            break

    return policies


def copy_policy(policy, src_client, dst_policies, dst_client, recreate):
    logger.debug(f"Copy policy {policy['PolicyName']}")
    dflt_version_id = policy['DefaultVersionId']

    policy_version = src_client.get_policy_version(PolicyArn=policy['Arn'], VersionId=dflt_version_id)

    # TODO: substitute src_account_id by dst_account_id if present in the policy document ?

    # Copy the policy in the dst_client but destroy the existing one if needed
    for dst_pol in dst_policies:
        if dst_pol['PolicyName'] == policy['PolicyName']:
            if recreate:
                logger.info(f"Policy {policy['PolicyName']} already exists in destination Account, we recreate it !")
                dst_client.delete_policy(PolicyArn=dst_pol['Arn'])
            else:
                logger.error(f"Policy {policy['PolicyName']} already exists in destination Account - use '--recreate'")
                return

    response = dst_client.create_policy(
        PolicyName=policy['PolicyName'],
        Path=policy['Path'],
        PolicyDocument=json.dumps(policy_version['PolicyVersion']['Document']),
        Description=policy['Description'] if 'Description' in policy else '',
        Tags=policy['Tags'] if 'Tags' in policy else [],
    )


if __name__ == '__main__':
    # standalone & batch mode
    import argparse
    import boto3

    usage = "%(prog)s --src-profile name --dst-profile name [--policy name] [-v|--verbose] [-r|--recreate]"

    parser = argparse.ArgumentParser(
        description="Copy Policy Objects from a source account to a destination account",
        usage=usage
    )
    parser.add_argument("--src-profile", nargs='?', help="Name of source profile in .aws/config", required=True)
    parser.add_argument("--dst-profile", nargs='?', help="Name of destination profile in .aws/config or .aws/credentials", required=True)
    parser.add_argument("--policy", nargs='?', help="Name of Policy to copy (All by default)", default=None)
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

    copy_policies(src_client, dst_client, opts.policy, opts.recreate)


