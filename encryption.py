import sys
import boto3
import botocore
import argparse

# - 0 : pending
# - 16 : running
# - 32 : shutting-down
# - 48 : terminated
# - 64 : stopping
# - 80 : stopped

client = boto3.client('ec2')
ec2 = boto3.resource('ec2')
client_kms = boto3.client('kms')


args = None


waiter_instance_exists = client.get_waiter('instance_exists')
waiter_instance_exists.config.delay = 5             # default 15 Sec
waiter_instance_exists.config.max_attempts = 10     # default 40

waiter_instance_stopped = client.get_waiter('instance_stopped')
waiter_instance_stopped.config.delay = 5
waiter_instance_stopped.config.max_attempts = 80

waiter_instance_running = client.get_waiter('instance_running')
waiter_instance_running.config.delay = 5

waiter_snapshot_complete = client.get_waiter('snapshot_completed')
waiter_snapshot_complete.config.delay = 5
waiter_snapshot_complete.config.max_attempts = 240

waiter_volume_available = client.get_waiter('volume_available')
waiter_volume_available.config.delay = 5

waiter_volume_inuse = client.get_waiter('volume_in_use')
waiter_volume_inuse.config.delay = 5

def main():
    global args

    parser = argparse.ArgumentParser(description='Encrypts EC2 Volumes using KMS.')
    parser.add_argument('-i', '--instance',
                        help='Instance to encrypt volume on.', required=False)
    parser.add_argument('-key', '--customer_master_key',
                        help='Customer master key', required=True)
    # parser.add_argument('-p', '--profile',
    #                     help='Profile to use', required=False)
    parser.add_argument('-r', '--region',
                        help='Region of source volume', required=True)
    args = parser.parse_args()

    # Check region is valid
    regions_list = client.describe_regions()['Regions']
    if not any(each_region['RegionName'] == args.region for each_region in regions_list):
        sys.exit('Invalid region parameter, Please try again')

    # Check CMK valid
    cmk_list = client_kms.list_keys()['Keys']
    if not any(cmk['KeyId'] == args.customer_master_key for cmk in cmk_list):
        print('Customer Master Key is not available for the region {}'.format(args.region))
        sys.exit()

    return args.instance


def ebs_encryption(instance):
    all_mappings = []
    volume_data = []

# Check whether Instance is exist
    print('---Checking instance ({})'.format(instance.id))

    try:
        waiter_instance_exists.wait(
            InstanceIds=[
                instance.id,
            ]
        )

    except botocore.exceptions.WaiterError as e:
        sys.exit('Unable to connect to ec2 service {}'.format(e))

    if instance.state['Code'] == 48:
        print('---Instance ({}) is terminated'.format(instance.id))
        return
    else:
        print('---Instance {} is available'.format(instance.id))

# Getting Inventory of un-encrypted volumes mappings
    block_device_mappings = instance.block_device_mappings
    for device_mapping in block_device_mappings:
        volume_obj = ec2.Volume(device_mapping['Ebs']['VolumeId'])
        if not volume_obj.tags:
            volume_obj.create_tags(Tags=instance.tags)
        if not volume_obj.encrypted:
            all_mappings.append(
                {
                    'DeleteOnTermination': device_mapping['Ebs']['DeleteOnTermination'],
                    'VolumeId': device_mapping['Ebs']['VolumeId'],
                    'DeviceName': device_mapping['DeviceName'],
                    'volume': volume_obj,
                },
            )
    if not all_mappings:
        print(f'All volumes for the {instance.id} are encrypted')
        return True

# Stop Ec2 Instance
    if instance.state['Code'] == 80:
        print(f'Instance {instance.id} is already stopped, proceeding for the next step')
    else:
        instance_exit_states = [0, 32]
        if instance.state['Code'] in instance_exit_states:
            print('Instance is {} please make sure this instance is active.'.format(instance.state['Name']))
            return False

        # Validate successful shutdown if it is running or stopping
        if instance.state['Code'] is 16:
            instance.stop()

        try:
            waiter_instance_stopped.wait(
                InstanceIds=[
                    instance.id,
                ]
            )
            print(f'-- {instance.id} is stopped')
        except botocore.exceptions.WaiterError as e:
            print('ERROR: {}'.format(e))
            return False

    for current_volume_data in all_mappings:
        volume = current_volume_data['volume']

    # Take Snapshot of volume
        print('---Create snapshot of volume ({})'.format(volume.id))
        snapshot = ec2.create_snapshot(
            VolumeId=volume.id,
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': volume.tags,
                },
            ],
            Description='Snapshot of volume ({})'.format(volume.id),
        )
        try:
            waiter_snapshot_complete.wait(
                SnapshotIds=[
                    snapshot.id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            snapshot.delete()
            print('ERROR: {}'.format(e))
            return False
        print('--Snapshot ({}) created'.format(snapshot.id))
        current_volume_data['snapshot'] = snapshot

     #  Create encrypted snapshot
        snapshot_encrypted_dict = snapshot.copy(SourceRegion=args.region,
                                                Description='Encrypted copy of snapshot ({})'.format(snapshot.id),
                                                KmsKeyId=args.customer_master_key, Encrypted=True, )
        snapshot_encrypted = ec2.Snapshot(snapshot_encrypted_dict['SnapshotId'])
        try:
            waiter_snapshot_complete.wait(
                SnapshotIds=[
                    snapshot_encrypted.id,
                ],
            )
        except botocore.exceptions.WaiterError as e:
            snapshot.delete()
            snapshot_encrypted.delete()
            print('ERROR: {}'.format(e))
            return False
        print('--Encrypted snapshot({}) created'.format(snapshot_encrypted.id))
        current_volume_data['snapshot_encrypted'] = snapshot_encrypted

    # Create a encrypted volume from encrypted snapshot
        if volume.volume_type == 'io1':
            volume_encrypted = ec2.create_volume(
                SnapshotId=snapshot_encrypted.id,
                VolumeType=volume.volume_type,
                Iops=volume.iops,
                AvailabilityZone=instance.placement['AvailabilityZone']
            )
        else:
            volume_encrypted = ec2.create_volume(
                SnapshotId=snapshot_encrypted.id,
                VolumeType=volume.volume_type,
                AvailabilityZone=instance.placement['AvailabilityZone']
            )
        if volume.tags:
            volume_encrypted.create_tags(Tags=volume.tags)

        try:
            waiter_volume_available.wait(
                VolumeIds=[
                    volume_encrypted.id,
                ],
            )
        except botocore.exceptions.WaiterError as e:
            snapshot.delete()
            snapshot_encrypted.delete()
            volume_encrypted.delete()
            print('ERROR: {}'.format(e))
            return False
        print('--Encrypted volume ({}) is created'.format(volume_encrypted.id))

    #Detaching the existing volume
        instance.detach_volume(
            VolumeId=volume.id,
            Device=current_volume_data['DeviceName']
        )
        try:
            waiter_volume_available.wait(
                VolumeIds=[
                    volume.id,
                ],
            )
        except botocore.exceptions.WaiterError as e:
            print('Error: {}'.format(e))
        print('---Detached existing volume {}'.format(volume.id))

    #Attaching encrypted volume
        instance.attach_volume(
            VolumeId=volume_encrypted.id,
            Device=current_volume_data['DeviceName']
        )
        try:
            waiter_volume_inuse.wait(
                VolumeIds=[
                  volume_encrypted.id,
                ],
            )
        except botocore.exceptions.WaiterError as e:
            print('Error: {}'.format(e))

        print('---Attached encrypted volume {}'.format(volume_encrypted.id))

    # Modify instance attributes
        instance.modify_attribute(
            BlockDeviceMappings=[
                {
                    'DeviceName': current_volume_data['DeviceName'],
                    'Ebs': {
                        'DeleteOnTermination': current_volume_data['DeleteOnTermination'],
                    },
                },
            ],
        )
        volume_data.append(current_volume_data)

    # Cleaning up resources
    print('---Clean up resources')
    for cleanup in volume_data:
        print('---Remove snapshot {}'.format(cleanup['snapshot'].id))
        cleanup['snapshot'].delete()
        print('---Remove encrypted snapshot {}'.format(cleanup['snapshot_encrypted'].id))
        cleanup['snapshot_encrypted'].delete()
        print('---Remove original volume {}'.format(cleanup['volume'].id))
        cleanup['volume'].delete()

#  Start instance
    print('---Starting instance')
    instance.start()
    try:
        waiter_instance_running.wait(
            InstanceIds=[
                instance.id,
            ]
        )
    except botocore.exceptions.WaiterError as e:
        print('ERROR: {}'.format(e))
        return False

    print("--Encryption finished for the instance's ({}) volumes".format(instance.id))

    return True



if __name__ == "__main__":
    if main():
        ebs_encryption(ec2.Instance(args.instance))
    else:
        for every_instance in ec2.instances.all():
            if not ebs_encryption(every_instance):
                break






