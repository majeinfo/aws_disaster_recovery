# List of our semantic tags
TAG_DEVICE = 'Device'
TAG_INSTANCE = 'Instance'
TAG_INSTANCE_TYPE = 'InstanceType'
TAG_ARCHITECTURE = 'Architecture'
TAG_ENA_SUPPORT = 'EnaSupport'
TAG_AVAILABILITY_ZONE = 'AvailabilityZone'
TAG_IAM_PROFILE_ARN = 'IamProfileArn'
TAG_IAM_PROFILE_ID = 'IamProfileId'
TAG_SECURITY_GROUPS = 'SecurityGroups'

# Set of useful and common function

def get_name_from_tags(tags):
    '''
    Find the Value associated with the Tag Key "Name" (if it exists)
    :param tags: array of {Key:k, Value:v}
    :return: the Name Value or ""
    '''
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']

    return ""

