'''
Example of use:
$ ./recreate_instance.py --instance-name MASTER --profile DFI-BKP --subnet-id xyz -v

This script must be launched in the target Account
'''
import logging
import time
import utils
from copy_security_groups import get_security_groups, SECURITY_GROUP_SRC_TAG

MAX_RESULTS = 200
RETRY_SECONDS = 5
ALL = "all"

logger = logging.getLogger('commands')


def find_instance_snapshots(client, account_id, instance_name):
    '''
    Find the snapshots with a tag matching the specified instance name.

    :param client:
    :param account_id:
    :param instance_name:
    :return: liste of instances
    '''
    def _set_instance(tag_value, snapshot):
        nonlocal found_snapshots
        found_snapshots[tag_value] = {
            'SnapshotId': snapshot['SnapshotId'],
            'StartTime': snapshot['StartTime'],
            'Tags': snapshot['Tags'],
        }

    # Find the snapshots that have the instance_name in the Name (tags['Name'])
    snapshots = []
    next_token = None
    while True:
        try:
            if next_token is None:
                snapshots_slice = client.describe_snapshots(MaxResults=MAX_RESULTS, OwnerIds=[account_id])
            else:
                snapshots_slice = client.describe_snapshots(MaxResults=MAX_RESULTS, OwnerIds=[account_id], NextToken=next_token)

            snapshots += snapshots_slice['Snapshots']
        except Exception as e:
            raise Exception(f"Could not retrieve snapshots description {e}")

        if 'NextToken' in snapshots_slice:
            logger.info("MaxResults is too low for describe_snpashots")
            next_token = snapshots_slice['NextToken']
        else:
            break

    found_snapshots = {}
    for snapshot in snapshots:
        logger.debug(f"Found {snapshot['SnapshotId']}")
        if not 'Tags' in snapshot:
            logger.debug("Snapshot discarded because it has no Tag")
            continue

        for tag in snapshot['Tags']:
            if tag['Key'] != 'Name':
                continue

            tag_value = tag['Value'].upper()
            if instance_name == tag_value or tag_value.startswith(instance_name + '-'):
                logger.debug(f"Found snapshot {snapshot['SnapshotId']} for {tag_value}")
                if tag_value not in found_snapshots:
                    _set_instance(tag_value, snapshot)
                else:
                    # In case of duplicated snapshots, take the latest one
                    if snapshot['StartTime'] > found_snapshots[tag_value]['StartTime']:
                        logger.info(f"Newer snapshot found for {tag_value}")
                        _set_instance(tag_value, snapshot)

                break

    return found_snapshots


def recreate_instance(client, account_id, instance_name, snapshots, recreate_ami, region, subnet_id):
    # Check if we found a snapshot for the system
    logger.info(f"Try to recreate instance {instance_name} from its snapshots...")
    if instance_name not in snapshots:
        raise Exception(f"No system snapshot found for instance {instance_name}")

    snapshot = snapshots[instance_name]

    #is_sys_disk = _get_tag_value(snapshot, 'SYSDISK')
    device_name = _get_tag_value(snapshot, utils.TAG_DEVICE)
    instance_type = _get_tag_value(snapshot, utils.TAG_INSTANCE_TYPE)
    availability_zone = _get_tag_value(snapshot, utils.TAG_AVAILABILITY_ZONE)
    ena_support = _get_tag_value(snapshot, utils.TAG_ENA_SUPPORT) == "True"
    architecture = _get_tag_value(snapshot, utils.TAG_ARCHITECTURE)
    sec_groups = _get_tag_value(snapshot, utils.TAG_SECURITY_GROUPS)

    # Find the matching security groups
    dst_sec_groups = _compute_dst_security_groups(client, sec_groups, subnet_id)
    logger.debug(f"New security groups={dst_sec_groups}")

    # Check if a new AMI must be created
    ami = client.describe_images(
        Filters=[{'Name': 'name', 'Values': [instance_name]}],
        Owners=[account_id]
    )

    # Delete existing AMI if needed
    if len(ami['Images']) and recreate_ami:
        client.deregister_image(ImageId=ami['Images'][0]['ImageId'])

    # Create a new AMI if required
    if len(ami['Images']) == 0 or recreate_ami:
        logger.info(f"Create AMI from snapshot {snapshot}")
        ami = client.register_image(
            Architecture=architecture,
            BlockDeviceMappings=[
                {
                    'DeviceName': device_name,
                    'Ebs': {
                        #'DeleteOnTermination': True,
                        'SnapshotId': snapshot['SnapshotId'],
                        #'VolumeSize': 20,
                        #'VolumeType': 'gp2'
                    }
                },
            ],
            EnaSupport=ena_support,
            Description=f"AMI created from Snapshot {snapshot['SnapshotId']}",
            Name=instance_name,
            RootDeviceName=device_name,
            VirtualizationType='hvm'
        )
        logger.info(f"AMI {ami['ImageId']} created")
    else:
        ami = ami['Images'][0]
        logger.info(f"AMI {ami['ImageId']} already exists and must not be recreated")

    # Create an instance from the AMI
    if subnet_id:   # needed for EC2-Classic
        instances = client.run_instances(
            # TODO: BlockDeviceMappings ?
            ImageId=ami['ImageId'],
            MinCount=1,
            MaxCount=1,
            InstanceType=instance_type,
            SubnetId=subnet_id,         # imply the AZ
            SecurityGroups=dst_sec_groups,
            TagSpecifications=[
                {'ResourceType': 'instance', 'Tags': [{'Key': 'Name', 'Value': instance_name}]}
            ]
        )

        # Must find the Region from the subnet-id
        region = instances['Instances'][0]['Placement']['AvailabilityZone'][:-1]
    else:
        instances = client.run_instances(
            # TODO: BlockDeviceMappings ?
            ImageId=ami['ImageId'],
            MinCount=1,
            MaxCount=1,
            InstanceType=instance_type,
            Placement={'AvailabilityZone': region + availability_zone[-1]}, # REQ: the dest region must have enough AZ !
            SecurityGroups=dst_sec_groups,
            TagSpecifications=[
                {'ResourceType': 'instance', 'Tags': [{'Key': 'Name', 'Value': instance_name}]}
            ]
        )

    # TODO: should add the instance name as the Name Tag of the system disk
    # TODO: Role and network configuration are missing (private+public+EIP)
    # TODO: To add a Role we need the IAM PassRole permission
    instance_id = instances['Instances'][0]['InstanceId']
    logger.info(f"Instance {instance_id} created")

    _recreate_volumes(client, instance_name, instance_id, snapshots, region + availability_zone[-1])


def _compute_dst_security_groups(client, src_sec_groups, subnet_id):
    # src_sec_groups = grp_name:grp_id:grp_name:grp_id:...
    logger.debug(f"Must find matching security groups for {src_sec_groups}")
    groups = src_sec_groups.split(':')

    # Find the VPC matching the subnet id
    response = client.describe_subnets(Filters=[{'Name': 'subnet-id', 'Values': [subnet_id]}])
    vpc_id = response['Subnets'][0]['VpcId']

    # Get the list of security groups for this VPC
    filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
    dst_sec_groups = get_security_groups(client, filters)
    for grp in dst_sec_groups:
        logger.debug(f"{grp['GroupId']}, {grp['GroupName']}, {grp['Tags'] if 'Tags' in grp else ''}")

    # Loop on the grp name then loop on the grp id to find the new name
    new_sec_groups = []
    for grp_name in groups[::2]:
        if grp_name == "": continue
        # We must find the dst_sec_group tagged with this grp_name
        logger.debug(f"grp_name={grp_name}")
        found = False
        for grp in dst_sec_groups:
            if 'Tags' not in grp:
                continue

            for tag in grp['Tags']:
                if tag['Key'] == SECURITY_GROUP_SRC_TAG and tag['Value'] == grp_name:
                    new_sec_groups.append(grp['GroupId'])
                    found = True
                    break

            if found: break

        if not found:
            logger.info(f"Could not find the matching security group for the original security group {grp_name}")

    # for grp_id in groups[1::2]:
    #     # We must find the dst_sec_group tagged with this grp_id
    #     found = False
    #     for grp in dst_sec_groups:
    #         if 'Tags' not in grp:
    #             continue
    #
    #         found = False
    #         for tag in grp['Tags']:
    #             if tag['Key'] == SECURITY_GROUP_SRC_TAG and tag['Value'] == grp_id:
    #                 dst_sec_groups.append(grp['GroupId'])
    #                 found = True
    #                 break
    #
    #     if not found:
    #         logger.info(f"Could not find the matching security group for the original security group {grp_id}")

    return new_sec_groups


def _recreate_volumes(ec2_client, instance_name, instance_id, snapshots, az):
    logger.info(f"Recreate volumes for instance {instance_name}")

    first_volume = True
    should_be_restarted = False

    for tag_name, snapshot in snapshots.items():
        if tag_name.upper() == instance_name:
            continue

        if first_volume:
            # If the created Instance has additional Volumes, it probably won't boot properly
            # so we must stop it first
            first_volume = False
            should_be_restarted = True

            state_name = 'initializing'
            while state_name != 'stopped':
                logger.info(f"Stopping Instance {instance_name} (state is {state_name})")
                time.sleep(RETRY_SECONDS)
                response = ec2_client.stop_instances(
                    InstanceIds=[instance_id],
                    Force=True
                )
                state_name = response['StoppingInstances'][0]['CurrentState']['Name']
                if state_name != 'stopped':
                    time.sleep(RETRY_SECONDS)

            logger.info(f"Instance {instance_name} stopped")

        logger.info(f"Create a volume from snapshot {snapshot['SnapshotId']} ({tag_name})")
        volume = client.create_volume(
            AvailabilityZone=az,
            SnapshotId=snapshot['SnapshotId'],
            TagSpecifications=[{
                'ResourceType': 'volume',
                'Tags': [
                    {'Key': 'Name', 'Value': tag_name},
                ]
            }]
        )

        device_name = _get_tag_value(snapshot, 'Device')
        logger.info(f"Attach Volume {volume['VolumeId']} as {device_name}")
        time.sleep(RETRY_SECONDS)
        client.attach_volume(
            Device=device_name,
            InstanceId=instance_id,
            VolumeId=volume['VolumeId']
        )

    # Volumes have been recreated and attached, start the instance if it has been stopped
    if should_be_restarted:
        state_name = 'stopped'
        while state_name != 'running':
            logger.info(f"Starting Instance {instance_name} (state is {state_name})")
            response = ec2_client.start_instances(
                InstanceIds=[instance_id]
            )
            state_name = response['StartingInstances'][0]['CurrentState']['Name']
            if state_name != 'running':
                time.sleep(RETRY_SECONDS)

        logger.info(f"Instance {instance_name} running")


def _get_tag_value(snapshot, tag_name):
    for tag in snapshot['Tags']:
        if tag['Key'] == tag_name:
            return tag['Value']

    raise Exception(f"Snapshot {snapshot['SnapshotId']} has no {tag_name} tag")


if __name__ == '__main__':
    # standalone & batch mode
    import argparse
    import boto3

    usage = "%(prog)s --instance-name name [--profile profile_name] --region region -s|--subnet-id subnet [-a|--recreate-ami] [-v|--verbose]"

    parser = argparse.ArgumentParser(
        description="Recreate an instance from the snapshoted volumes",
        usage=usage
    )
    parser.add_argument("-p", "--profile", nargs='?', help="Name of profile in .aws/config")
    parser.add_argument("-r", "--region", nargs='?', help="Name of the Region where are the snapshots and the instances", required=True)
    parser.add_argument("-i", "--instance-name", nargs='?', help="Name of the Instance to recreate", required=True)
    parser.add_argument("-a", "--recreate-ami", action="store_true", help="Recreate the AMI if it already exists", default=False)
    parser.add_argument("-s", "--subnet-id", nargs='?', help="Subnet ID", required=True) #default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug mode", default=False)
    opts = parser.parse_args()

    if opts.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.addHandler(logging.StreamHandler())

    session = boto3.Session(profile_name=opts.profile)
    if opts.region:
        client = session.client('ec2', region_name=opts.region)
    else:
        client = session.client('ec2')

    account_id = session.client('sts').get_caller_identity().get('Account')
    found_snapshots = find_instance_snapshots(client, account_id, opts.instance_name)
    recreate_instance(client, account_id, opts.instance_name, found_snapshots, opts.recreate_ami, opts.region, opts.subnet_id)
    logger.info("Instance recreated")
