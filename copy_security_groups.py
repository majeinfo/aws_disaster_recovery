'''
Example of use:
$ ./copy_security_groups.py --src-profil SRC --src-region eu-west-1 --dst-profil DST --dst-region eu-central-1 -v

The copied Security Group will be tagged with the key OriginalName and the value will be the original Id
'''
import datetime
import time
import logging
import botocore
import copy_vpcs
from utils import get_name_from_tags

MAX_RESULTS = 200
SECURITY_GROUP_SRC_TAG = 'SourceSecurityGroupId'

logger = logging.getLogger('commands')


def copy_security_groups(src_client, dst_client, dst_account_id, vpc_id=None, recreate=False):
    # Since SG depends on VpcId, we loop on VPC
    src_vpcs = copy_vpcs.get_all_vpcs(src_client)
    dst_vpcs = copy_vpcs.get_all_vpcs(dst_client)

    for src_vpc in src_vpcs:
        if vpc_id is not None and vpc_id != src_vpc['VpcId']:
            continue

        create_security_groups_of_vpc(src_vpc, dst_vpcs, dst_account_id, recreate)


def create_security_groups_of_vpc(src_vpc, dst_vpcs, dst_account_id, recreate):
    # First we must create all the SecGroups, but without any rules because SG can refer each other
    # In a second step, we will fill the rules
    filters=[{'Name': 'vpc-id', 'Values': [src_vpc['VpcId']]}]
    src_sec_groups = get_security_groups(src_client, filters)

    dst_vpc = copy_vpcs.create_vpc(src_client, dst_client, src_vpc, dst_vpcs, recreate)
    filters=[{'Name': 'vpc-id', 'Values': [dst_vpc['VpcId']]}]
    dst_sec_groups = get_security_groups(dst_client, filters)

    # Find the default destination group
    dst_default_group = None
    for dst_secgrp in dst_sec_groups:
        if dst_secgrp['GroupName'] == 'default':
            dst_default_group = dst_secgrp['GroupId']

    # For each found SG, we must create them but associated with the destination VpcId
    # We must also build a dict to know the matches betweeen the src_sec_grp_id and the dest_sec_grp_id
    matching_ids = {}
    for src_secgrp in src_sec_groups:
        logger.debug(f"Recreate {src_secgrp['GroupId']}, {src_secgrp['GroupName']}, {src_secgrp['Description']}, {src_secgrp['VpcId']}")
        dst_group_found = False
        for dst_group in dst_sec_groups:
            if 'Tags' in dst_group:
                for tag in dst_group['Tags']:
                    if tag['Key'] == SECURITY_GROUP_SRC_TAG and src_secgrp['GroupName'] == tag['Value']:
                        logger.info(f"Security Group {src_secgrp['GroupName']} already created")
                        dst_group_found = True
                        matching_ids[src_secgrp['GroupId']] = dst_group['GroupId']

        if dst_group_found:
            continue

        src_name = get_name_from_tags(src_secgrp['Tags']) if 'Tags' in src_secgrp else ''
        if src_name == 'default' or src_secgrp['GroupName'] == 'default':
            logger.info("Default Security Group skipped")
            # Find the default SecGoup in the destination
            matching_ids[src_secgrp['GroupId']] = dst_default_group
            continue

        dst_grp = dst_client.create_security_group(
            Description=src_secgrp['Description'],
            GroupName=src_secgrp['GroupName'],
            VpcId=dst_vpc['VpcId'],
            TagSpecifications=[
                {
                    'ResourceType': 'security-group',
                    'Tags': [
                        {'Key': 'Name', 'Value': src_name},
                        {'Key': SECURITY_GROUP_SRC_TAG, 'Value': src_secgrp['GroupName']}
                    ]
                },
            ]
        )
        logger.info(f"Security Group {src_secgrp['GroupId']} recreated with Id {dst_grp['GroupId']}")
        matching_ids[src_secgrp['GroupId']] = dst_grp['GroupId']

    # Now, we can loop on the Inbound Rules and copy them (TODO: outbound rules not supported)
    for src_secgrp in src_sec_groups:
        dst_grp_id = matching_ids[src_secgrp['GroupId']]
        logger.info(f"Apply Rules for Security Group (src={src_secgrp['GroupId']}, dst={dst_grp_id})")

        # src_rules = src_client.describe_security_group_rules(
        #     Filters=[{'Name': 'group-id', 'Values': [src_secgrp['GroupId']]}]
        # )

        owner_id = src_secgrp['OwnerId']
        ip_perms = []
        for ip_perm in src_secgrp['IpPermissions']:
            logger.debug(f"Permissions: {ip_perm}")

            # We must loop and change Id in the UserIdGroupPairs array
            for pair in ip_perm['UserIdGroupPairs']:
                if 'GroupId' in pair:
                    pair['GroupId'] = matching_ids[pair['GroupId']]
                if 'UserId' in pair and pair['UserId'] == owner_id:
                    pair['UserId'] = dst_account_id

            ip_perms.append(ip_perm)

        # dst_rules = []
        # for src_rule in src_rules['SecurityGroupRules']:
        #     dst_rule = {}
        #     if 'FromPort' in src_rule:
        #         dst_rule['FromPort'] = src_rule['FromPort']
        #     if 'ToPort' in src_rule:
        #         dst_rule['ToPort'] = src_rule['ToPort']
        #     if 'IpProtocol' in src_rule:
        #         dst_rule['IpProtocol'] = src_rule['IpProtocol']
        #     if 'CidrIpv4' in src_rule:
        #         dst_rule['CidrIpv4'] = src_rule['CidrIpv4']
        #     if 'CidrIpv6' in src_rule:
        #         dst_rule['CidrIpv6'] = src_rule['CidrIpv6']
        #
        #     dst_rules.append({'SecurityGroupRule': dst_rule})

        # Modify the Inbound rules
        # response = dst_client.modify_security_group_rules(
        #     GroupId=dst_grp_id,
        #     SecurityGroupRules=dst_rules,
        # )
        # logger.info(f"Security Group Rules recreated")

        try:
            response = dst_client.authorize_security_group_ingress(
                GroupId=dst_grp_id,
                IpPermissions=ip_perms,
                #SecurityGroupRuleDescriptions=sec_rule_desc,
            )
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                pass
            else:
                raise error


        # TODO: createTags ????


def get_security_groups(client, filters):
    sec_groups = []
    next_token = None

    while True:
        if next_token is None:
            sec_groups_slice = client.describe_security_groups(Filters=filters, MaxResults=MAX_RESULTS)
        else:
            sec_groups_slice = client.describe_security_groups(Filters=filters, MaxResults=MAX_RESULTS, NextToken=next_token)

        sec_groups += sec_groups_slice['SecurityGroups']

        if 'NextToken' in sec_groups_slice:
            logger.info("MaxResults is too low for describe_security_groups, go on with next_token...")
            next_token = sec_groups_slice['NextToken']
        else:
            break

    return sec_groups


if __name__ == '__main__':
    # standalone & batch mode
    import argparse
    import boto3

    usage = "%(prog)s --src-profile name [--src-region=REGION] --dst-profile name [--dst-region=REGION] [--vpc-id vpc_id] [-v|--verbose]"

    parser = argparse.ArgumentParser(
        description="Copy Security Groups from a source account to a destination account",
        usage=usage
    )
    parser.add_argument("--src-profile", nargs='?', help="Name of source profile in .aws/config", required=True)
    parser.add_argument("--src-region", nargs='?', help="Region where the source EBS are located", default=None)
    parser.add_argument("--dst-profile", nargs='?', help="Name of destination profile in .aws/config or .aws/credentials", required=True)
    parser.add_argument("--dst-region", nargs='?', help="Region where the destination EBS must be created", default=None)
    parser.add_argument("--vpc-id", nargs='?', help="Optional VPC Id to recreate from source", default=None)
    parser.add_argument("-r", "--recreate", action="store_true", help="Recreate the Security Groups if they already exist in the destination", default=False)
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug mode", default=False)
    opts = parser.parse_args()

    if opts.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.addHandler(logging.StreamHandler())

    src_session = boto3.Session(profile_name=opts.src_profile, region_name=opts.src_region) #if opts.src_profile_name else boto3.Session()
    src_client =  src_session.client('ec2')

    dst_session = boto3.Session(profile_name=opts.dst_profile, region_name=opts.dst_region) if opts.dst_profile else boto3.Session(region_name=opts.dst_region)
    dst_client =  dst_session.client('ec2')
    account_id = dst_session.client('sts').get_caller_identity().get('Account')

    sec_groups = copy_security_groups(src_client, dst_client, account_id, opts.vpc_id, opts.recreate)


