'''
Example of use:
$ ./copy_snapshots.py --src-profil SRC --src-region eu-west-1 --dst-profil DST --dst-region eu-central-1 -v

Note: this script cannot use any multithread or multiprocessing technics because boto3 in only single-threaded

TODO: should add a flag for sync(default)/async
TODO: should add a notification somewhere ?
'''
import datetime
import time
import logging

MAX_RESULTS = 200

logger = logging.getLogger('commands')


def get_snapshots(account_id, dst_client, src_ec2):
    '''
    :param account_id str: account ID who owns the snapshots
    :param dst_client boto3 Client: client who must copy the snapshots
    :param dst_ec2 ec2 Client
    :return: list of snaphosts to be copied
    '''
    today = datetime.date.today()

    snapshots_to_be_copied = []
    next_token = None
    while True:
        if next_token is None:
            snapshots = dst_client.describe_snapshots(OwnerIds=[account_id], MaxResults=MAX_RESULTS)
        else:
            snapshots = dst_client.describe_snapshots(OwnerIds=[account_id], MaxResults=MAX_RESULTS, NextToken=next_token)

        for snapshot in snapshots['Snapshots']:
            logger.debug(f"Analysis of snapshot {snapshot['SnapshotId']}")
            logger.debug(f"{snapshot}")

            # StartTime must be the today date
            start_time = snapshot['StartTime']
            if today.year != start_time.year or today.month != start_time.month or today.day != start_time.day:
                logger.debug(f"{snapshot['SnapshotId']} skipped because of wrong date")
                continue

            snapshot_ori = src_ec2.Snapshot(snapshot['SnapshotId'])

            # Compute tags that must be copied
            ori_tags = []
            if snapshot_ori.tags:
                for tag in snapshot_ori.tags:
                    # Skip tags added by the DLM
                    if tag['Key'].startswith('aws:') or tag['Key'].startswith('dlm'):
                        continue

                    ori_tags.append(tag)

            snapshots_to_be_copied.append({
                'SnapshotId': snapshot['SnapshotId'],
                'VolumeId': snapshot['VolumeId'],
                'Tags': ori_tags,
            })

        if 'NextToken' in snapshots:
            logger.info("MaxResults is too low for describe_snapshots, go on with next_token...")
            next_token = snapshots['NextToken']
        else:
            break

    return snapshots_to_be_copied


def copy_snapshots(dst_client, dst_ec2, snapshot, src_region, dst_region):
    '''
    :param dst_client: desctibation account
    :param dst_ec2:
    :param snapshot: definition of the snapshot
    :param src_region str:
    :param dst_region str:
    :return:
    '''
    logger.info(f"New snapshot Id: {snapshot['SnapshotId']} must be created from region {src_region} to region {dst_region}")
    logger.debug(f"Original tags are {snapshot['Tags']}")

    try:
        res = dst_client.copy_snapshot(
            SourceRegion=src_region,
            SourceSnapshotId=snapshot['SnapshotId'],
            Description=f"From VolumeId {snapshot['VolumeId']} and SnapshotId {snapshot['SnapshotId']}",
            DestinationRegion=dst_region,
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot', 'Tags': snapshot['Tags'] + [{'Key': 'SnapshotId', 'Value': snapshot['SnapshotId']}]
                }
            ]
        )

        logger.info(f"New snapshot Id: {res['SnapshotId']} started")

        # Wait until snapshot created
        time.sleep(3)
        while True:
            snapshot = dst_ec2.Snapshot(res['SnapshotId'])
            if snapshot.progress == '100%':
                break

            time.sleep(5)

        logger.info(f"New snapshot Id: {res['SnapshotId']} created")
    except Exception as e:
        logger.error(f"Exception caught:{e}")


if __name__ == '__main__':
    # standalone & batch mode
    import argparse
    import boto3

    usage = "%(prog)s --src-profile name [--src-region=REGION] --dst-profile name [--dst-region=REGION] [-v|--verbose]"

    parser = argparse.ArgumentParser(
        description="Copy Snapshots from a source account to a destination account and preserve the tags",
        usage=usage
    )
    parser.add_argument("--src-profile", nargs='?', help="Name of source profile in .aws/config", required=True)
    parser.add_argument("--src-region", nargs='?', help="Region where the source EBS are located", default=None)
    parser.add_argument("--dst-profile", nargs='?', help="Name of destination profile in .aws/config or .aws/credentials", required=True)
    parser.add_argument("--dst-region", nargs='?', help="Region where the destination EBS must be created", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug mode", default=False)
    opts = parser.parse_args()

    if opts.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.addHandler(logging.StreamHandler())

    src_session = boto3.Session(profile_name=opts.src_profile, region_name=opts.src_region) #if opts.src_profile_name else boto3.Session()
    src_client =  src_session.client('ec2')

    dst_session1 = boto3.Session(profile_name=opts.dst_profile, region_name=src_session.region_name) if opts.dst_profile else boto3.Session(region_name=src_session.region_name)
    dst_client1 =  dst_session1.client('ec2')

    if opts.dst_region:
        dst_session2 = boto3.Session(profile_name=opts.dst_profile, region_name=opts.dst_region)
    else:
        dst_session2 = boto3.Session(profile_name=opts.dst_profile)

    dst_client2 =  dst_session2.client('ec2')

    src_ec2 = src_session.resource('ec2', region_name=src_session.region_name)  # Needed to read the snapshot Tags with the source account
    dst_ec2 = dst_session1.resource('ec2', region_name=dst_session2.region_name)

    account_id = src_session.client('sts').get_caller_identity().get('Account')

    snapshots = get_snapshots(account_id, dst_client1, src_ec2)

    # Cannot use parallelism
    for snapshot in snapshots:
        copy_snapshots(dst_client2, dst_ec2, snapshot, src_session.region_name, opts.dst_region if opts.dst_region else dst_session2.region_name)
