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

