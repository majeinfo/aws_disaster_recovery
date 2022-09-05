# Building a Disaster Recovery Plan for AWS

## What are the threats we must face to in the Cloud ?

We use Cloud resources since 2010 (mainly AWS) and even if we try to design 
our architectures with the H/A property in mind, there are some rare, 
but not null, risks we must think about.

For example, we have experimented an outage due to a datacenter in fire
(it is located at Dublin and has been stroken by a lightning). AWS decided
to shutdown the damaged datacenter but fortunately, our applications were 
distributed on the other datacenters located in Dublin, too.

OK, we survived, but what would have happened if the 3 datacenters would have become
simultaneously unreachable ? I let you imagine the scenarios why this could 
happen !

To avoid this unavailability, AWS describes 3 solutions : the "pilot-light" 
pattern, the "hot-standby" pattern and the "multi-site" pattern. 
These patterns are useful and valuable, but, wait there is more...

One day, some of our
Access Keys have been pushed in a GitHub repository (but it happened
in summer 2022 to Microsoft too !). Few hours later, our keys have been
used to create resources in unusual Regions. This has been quickly fixed
(thanks to AWS monitoring !). But what would have happened if instead of
creating new resources (to mine Bitcoins !), the robot would have 
deleted the running EC2 instances, the S3 Buckets, 
the Route53 zone definitions, etc... ?

## The chosen strategy

Some of you will argue that building a DR Plan may be quite easy in the Cloud : 
if you use Terraform, CloudFormation or Ansible playbooks and if you are sure
they are up-to-date, use them ! But this is not our case !

**We want something as reliable and as cheap as possible.**

1. Because our Access Keys or SSH access to an instance with some sufficient
IAM Role could be compromised, we decide to create a new AWS Account : 
the "DR Account".
2. The resources created with this new Account will be located in a
distinct Region 
3. AWS Objects that are free are recreated in the new Account 
4. Data (S3 Buckets, backups...) are copied in the new Account
5. Expensive resources must be recreated but only in case of trouble

## Technical details

1. Scheduled Python scripts copy charge-free objects in the DR Account :
VPC, Subnet, SecurityGroup
2. The EC2 Instances that must be recreated in the RD Account, must be
tagged with a unique Name, their attached EBS Disks must also be tagged
with a Name prefixed by the Instance Name. For example, an Instance named
`MASTER` may have a system Disk named `MASTER` and a data Disk named
`MASTER-DATA`
3. The system Disks are also tagged with `SYSDISK: True`
4. All the Disks are tagged with `MUSTSNAP: True`
5. The `tag_volumes.py` script is executed with the original Account to
add new semantic tags to the Volumes (VERY IMPORTANT)
6. Then a LifeCycle Policy will take a Snapshot of all Disks tagged 
`MUSTSNAP: True` and the Snapshots are shared with the RD Account (note that
cross-region copy of a snapshot loses the tags ! This is also true for
cross-account copying...)
7. The `copy_snapshots.py` script is executed in the DR Account to copy the
Snapshots in the DR Account by preserving the original tags
8. In case of DR, use the `recreate_instance.py` script to recreate an EC2 
Instance (by creating a new AMI, new Volumes and then launching the
Instance)

## Limitations

1. The DR Region must have at least as many AZ as the original one
2. If the limits of AWS resources usage have been increased in the 
original Region, make sure the same limits have been raised in the DR Region
3. IPv6 is not handled
4. Outbound Rules in Security Groups are not handled
5. EC2-Classic is not supported

## TODO

The following objects must also be copied in the DR Account :
1. IAM Role
2. User & Group and Policy
3. Target Group
4. CloudFront distribution
