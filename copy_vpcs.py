'''
Example of use:
$ ./copy_vpc.py --src-profil SRC --src-region eu-west-1 --dst-profil DST --dst-region eu-central-1 --vpc-id xxx -v

The copied VPC will be tagged with the key OriginalName and the value will be the original Id
'''
import datetime
import time
import logging
from utils import get_name_from_tags

MAX_RESULTS = 200
VPC_SRC_TAG = 'SourceVpcId'
SUBNET_SRC_TAG = 'SourceSubnetId'
DHCP_OPTIONS_SRC_TAG = 'SourceDhcpOptionsId'

logger = logging.getLogger('commands')


def copy_vpcs(src_client, dst_client, vpc_id=None, recreate=False):
    '''
    Copy the definition of VPCs from source to destination Account

    :param src_client: source account
    :param dst_client: destination account
    :param vpc_id: VpcId of source VPC or None to copy all VPCs
    :param recreate: recreate VPC in destination or not
    :return:
    '''

    src_vpcs = get_all_vpcs(src_client)
    dst_vpcs = get_all_vpcs(dst_client)

    # Must also recreate the ACL, Dhcp Options and route table
    #_create_dhcp_options(src_client, dst_client)

    # Copy specified VPCs (one or all ?)
    for src_vpc in src_vpcs:
        if vpc_id is not None and vpc_id != src_vpc['VpcId']:
            continue

        logger.info(f"{src_vpc['VpcId']}, {src_vpc['CidrBlock']}")
        create_vpc(src_client, dst_client, src_vpc, dst_vpcs, recreate)


def get_all_vpcs(client):
    # Get all source VPCs
    vpcs = []
    next_token = None
    while True:
        if next_token is None:
            vpcs_slice = client.describe_vpcs(MaxResults=MAX_RESULTS)
        else:
            vpcs_slice = client.describe_vpcs(MaxResults=MAX_RESULTS, NextToken=next_token)

        vpcs += vpcs_slice['Vpcs']

        if 'NextToken' in vpcs_slice:
            logger.info("MaxResults is too low for describe_vpcs, go on with next_token...")
            next_token = vpcs_slice['NextToken']
        else:
            break

    return vpcs


def create_vpc(src_client, dst_client, src_vpc, dst_vpcs, recreate):
    # Check if VPC already created in destination
    logger.info(f"Check if VPC {src_vpc['VpcId']} must be recreated")

    # Skip default
    if src_vpc['IsDefault']:
        logger.info("skip default VPC")

    for dst_vpc in dst_vpcs:
        if 'Tags' in dst_vpc:
            for tag in dst_vpc['Tags']:
                if tag['Key'] == VPC_SRC_TAG and src_vpc['VpcId'] == tag['Value']:
                    logger.info(f"VPC {src_vpc['VpcId']} already created")
                    if not recreate:
                        logger.info("VPC not recreated")
                        return dst_vpc

                    # We must recreate it, so we must delete if first
                    _delete_vpc(dst_client, dst_vpc['VpcId'])

    # Must copy the src VPC
    # Get the original Name
    logger.debug(src_vpc)
    src_name = get_name_from_tags(src_vpc['Tags']) if 'Tags' in src_vpc else ''

    vpc = dst_client.create_vpc(
        CidrBlock=src_vpc['CidrBlock'],
        InstanceTenancy=src_vpc['InstanceTenancy'],
        TagSpecifications=[
            {
                'ResourceType': 'vpc',
                'Tags': [
                    {'Key': 'Name', 'Value': src_name},
                    {'Key': VPC_SRC_TAG, 'Value': src_vpc['VpcId']}
                ]
            },
        ]
    )
    dst_vpc_id = vpc['Vpc']['VpcId']

    # # must copy ACL, route table, DHCP options, subnets
    # src_route = src_client.describe_route_tables(
    #     Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}],
    #     MaxResults=100
    # )
    # logger.debug(src_route)

    # Recreate the Subnets
    src_subnets = src_client.describe_subnets(
        Filters=[{'Name': 'vpc-id', 'Values': [src_vpc['VpcId']]}],
        MaxResults=MAX_RESULTS
    )
    logger.debug(src_subnets)

    for src_subnet in src_subnets['Subnets']:
        # Try to use the original name
        src_name = get_name_from_tags(src_subnet['Tags']) if 'Tags' in src_subnet else ''

        dst_subnet = dst_client.create_subnet(
            VpcId=dst_vpc_id,
            CidrBlock=src_subnet['CidrBlock'],
            AvailabilityZone=dst_client.meta.region_name + src_subnet['AvailabilityZone'][-1],
            TagSpecifications=[
                {
                    'ResourceType': 'subnet',
                    'Tags': [
                        {'Key': 'Name', 'Value': src_name},
                        {'Key': SUBNET_SRC_TAG, 'Value': src_subnet['SubnetId']}
                    ]
                },
            ]
        )
        logger.info(f"Subnet {src_subnet['SubnetId']} recreated")

    return vpc['Vpc']


def _delete_vpc(dst_client, vpc_id):
    logger.info(f"Recreate VPC {vpc_id}")

    # Must delete dependencies first
    dst_subnets = dst_client.describe_subnets(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}],
        MaxResults=MAX_RESULTS
    )
    for subnet in dst_subnets['Subnets']:
        dst_client.delete_subnet(SubnetId=subnet['SubnetId'])

    dst_client.delete_vpc(VpcId=vpc_id)


def _create_dhcp_options(src_client, dst_client):
    src_dhcp_options = src_client.describe_dhcp_options(
        MaxResults=MAX_RESULTS
    )
    logger.debug(src_dhcp_options)

    dst_dhcp_options = dst_client.describe_dhcp_options(
        MaxResults=MAX_RESULTS
    )
    logger.debug(src_dhcp_options)

    # Loop on the src options and check if they have already been created or not
    for src_opt in src_dhcp_options['DhcpOptions']:
        # Loop in the dest to check if options already created
        for dst_opt in dst_dhcp_options['DhcpOptions']:
            logger.info(dst_opt)


if __name__ == '__main__':
    # standalone & batch mode
    import argparse
    import boto3

    usage = "%(prog)s --src-profile name [--src-region=REGION] --dst-profile name [--dst-region=REGION] [--vpc-id id] [-r|--recreate] [-v|--verbose]"

    parser = argparse.ArgumentParser(
        description="Copy Security Groups from a source account to a destination account",
        usage=usage
    )
    parser.add_argument("--src-profile", nargs='?', help="Name of source profile in .aws/config", required=True)
    parser.add_argument("--src-region", nargs='?', help="Region where the source EBS are located", default=None)
    parser.add_argument("--dst-profile", nargs='?', help="Name of destination profile in .aws/config or .aws/credentials", required=True)
    parser.add_argument("--dst-region", nargs='?', help="Region where the destination EBS must be created", default=None)
    parser.add_argument("--vpc-id", nargs='?', help="Optional VPC Id to recreate from source", default=None)
    parser.add_argument("-r", "--recreate", action="store_true", help="Recreate VPC and Subnet if they already exist in the destination", default=False)
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

    sec_groups = copy_vpcs(src_client, dst_client, opts.vpc_id, opts.recreate)


