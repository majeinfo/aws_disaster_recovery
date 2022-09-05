'''
Example of use:
$ ./tag_volumes.py --profile name --region eu-west-1 --system-tag SYSDISK --volume-tag MUSTSNAP

This script must be launched by the Account that must be restored in another account.
'''
import logging

MAX_RESULTS = 200

logger = logging.getLogger('commands')


def tag_volumes(client, system_tag, volume_tag):
    '''Tag all the volumes that must be duplicated in another Region.

    :param client: boto3 client
    :param system_tag str: value of the Tag used to mark system disks
    :param volume_tag str: value of the Tag used to mark a disk to be tagged
    :return dict: return the count of instances and volumes examined and tagged
    '''

    # Find all instances (handle the native pagination) and build
    # a dict with InstanceId as key
    instance_ids = {}
    next_token = None
    while True:
        try:
            if next_token is None:
                instances_slice = client.describe_instances(MaxResults=MAX_RESULTS)
            else:
                instances_slice = client.describe_instances(MaxResults=MAX_RESULTS, NextToken=next_token)

            for resv in instances_slice['Reservations']:
                for instance in resv['Instances']:
                    instance_ids[instance['InstanceId']] = instance
        except Exception as e:
            raise Exception(f"Could not retrieve instances description {e}")

        if 'NextToken' in instances_slice:
            logger.info("MaxResults is too low for describe_instances, go on with next_token...")
            next_token = instances_slice['NextToken']
        else:
            break

    logger.debug('List of found instances:')
    logger.debug(list(instance_ids.keys()))
    instances_count = len(instance_ids.keys())

    # Find all the volumes that must be snapshotted
    volumes = []
    next_token = None
    while True:
        try:
            if next_token is None:
                volumes_slice = client.describe_volumes(MaxResults=MAX_RESULTS, Filters=[{'Name': f'tag:{volume_tag}', 'Values': ['True']}])
            else:
                volumes_slice = client.describe_volumes(MaxResults=MAX_RESULTS, Filters=[{'Name': f'tag:{volume_tag}', 'Values': ['True']}], NextToken=next_token)

            volumes += volumes_slice['Volumes']
        except Exception as e:
            raise Exception(f"Could not retrieve volumes description {e}")

        if 'NextToken' in volumes_slice:
            logger.info("MaxResults is too low for describe_volumes, go on with next_token...")
            next_token = volumes_slice['NextToken']
        else:
            break

    logger.debug(f'List of Volumes that have the {volume_tag} Tag:')
    logger.debug(volumes)
    volumes_count = len(volumes)

    for volume in volumes:
        # Add a tag with attachment info
        logger.debug(f"Handling Volume {volume['VolumeId']}")
        attachments = volume['Attachments']

        # TODO: handle only ONE attachment
        if len(attachments) > 1:
            logger.info(f"Volume {volume['VolumeId']} is multi-attached. Only the first attachment will be managed")

        if not len(attachments) or attachments[0]['State'] != 'attached':
            logger.info(f"Volume {volume['VolumeId']} is not attached")
            continue

        instance_id = attachments[0]['InstanceId']
        volume_id = volume['VolumeId']
        if instance_id not in instance_ids:
            raise Exception(f"No instance found for InstanceId {instance_id} referenced by volume {volume_id}")

        instance = instance_ids[instance_id]
        device = attachments[0]['Device']
        instance_name = _get_instance_from_id(volume_id, instance_id, instance)
        tags = [
            {'Key': 'Instance', 'Value': instance_name},
            {'Key': 'Device', 'Value': device},
        ]

        # Test if volume is a SYSDISK volume
        for tag in volume['Tags']:
            if tag['Key'] == system_tag:
                logger.debug('This Volume is a System Volume')
                tags.append({'Key': 'InstanceType', 'Value': instance['InstanceType']})
                tags.append({'Key': 'Architecture', 'Value': instance['Architecture']})
                tags.append({'Key': 'EnaSupport', 'Value': instance['EnaSupport']})
                tags.append({'Key': 'AvailabilityZone', 'Value': instance['Placement']['AvailabilityZone']})

                if 'IamInstanceProfile' in instance:
                    iam_profile_arn = instance['IamInstanceProfile']['Arn']
                    iam_profile_id = instance['IamInstanceProfile']['Id']
                    tags.append({'Key': 'IamProfileArn', 'Value': iam_profile_arn})
                    tags.append({'Key': 'IamProfileId', 'Value': iam_profile_id})

                security_groups = _linearize(instance['SecurityGroups'])
                tags.append({'Key': 'SecurityGroups', 'Value': security_groups})
                break

        client.create_tags(Resources=[volume_id], Tags=tags)
        logger.debug(f"Volume {volume_id} tagged")

    return {"instances_count": instances_count, "volumes_count": volumes_count}


def _get_instance_from_id(volume_id, instance_id, instance):
    for tag in instance['Tags']:
        if tag['Key'] == 'Name':
            return tag['Value']

    raise Exception(f"Instance {instance_id} has no Name tag !")


def _linearize(security_groups):
    sec = ""
    for security_goup in security_groups:
        sec = sec + security_goup['GroupName'] + ':' + security_goup['GroupId'] + ':'

    return sec


if __name__ == '__main__':
    # standalone & batch mode
    import argparse
    import boto3

    usage = "%(prog)s [-p|--profile name] [-r|--region=REGION] [-s|--system-tag=SYSDISK] [-t|--volume-tag=MUSTSNAP] [-v|--verbose]"

    parser = argparse.ArgumentParser(
        description="Add semantic Tags to marker Volumes",
        usage=usage
    )
    parser.add_argument("-p", "--profile", nargs='?', help="Name of profile in .aws/config")
    parser.add_argument("-r", "--region", nargs='?', help="Region where the EBS are located", default=None)
    parser.add_argument("-s", "--system-tag", nargs='?', help="Name of the Tag put on System Disk", default="SYSDISK")
    parser.add_argument("-t", "--volume-tag", nargs='?', help="Name of the Tag put on an EBS that must ne snapshotted", default="MUSTSNAP")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Debug mode", default=False)
    opts = parser.parse_args()

    if opts.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.addHandler(logging.StreamHandler())

    session = boto3.Session(profile_name=opts.profile) if opts.profile else boto3.Session()
    client =  session.client('ec2', region_name=opts.region) if opts.region else session.client('ec2')

    result = tag_volumes(client, opts.system_tag, opts.volume_tag)
    logger.info(f"{result['instances_count']} Instances examined and {result['volumes_count']} Volumes tagged")

