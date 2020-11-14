import boto3
from botocore.exceptions import ClientError

class AwsConnection:

     def __init__(self, region, security_group_tag, instance_tag, key_tag):
          self.ec2_resource = boto3.resource('ec2', region_name = region)
          self.ec2_client = boto3.client('ec2', region_name = region)
          self.security_group_tag = security_group_tag
          self.instance_tag = instance_tag
          self.key_tag = key_tag
          self.key_name = None
          self.security_group_id = None
          self.vpc_id = self.ec2_client.describe_vpcs().get('Vpcs', [{}])[0].get('VpcId', '')

     def create_instance(self, image_id, user_data):
          print("\nCreating instance, image_id=%s, key_name=%s" % (image_id, self.key_name))
          try:
               waiter = self.ec2_client.get_waiter('instance_status_ok')
               # create a new EC2 instance
               instance = self.ec2_resource.create_instances(
                    ImageId=image_id,
                    MinCount=1,
                    MaxCount=1,
                    InstanceType='t2.micro',
                    SecurityGroupIds=[self.security_group_id],
                    UserData=user_data,
                    KeyName=self.key_name,
                    TagSpecifications=[{'ResourceType': 'instance', 'Tags': [self.instance_tag]}]
               )

               waiter.wait(InstanceIds=[instance[0].id])
               public_ip = self.ec2_client.describe_instances(InstanceIds=[instance[0].id])['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0]['PrivateIpAddresses'][0]['Association']['PublicIp']
               print("Instance %s created and checked, public_ip=%s" % (instance[0].id, public_ip))
               return public_ip, instance[0].id

          except ClientError as e:
               print('Error', e)

          return

     def create_key_pair(self, key_name, file):
          print("\nCreating key %s" % (key_name))

          try:
               self.key_name = key_name
               response = self.ec2_client.create_key_pair(
                    KeyName=key_name,
                    TagSpecifications=[{'ResourceType': 'key-pair', 'Tags': [self.key_tag]}]
               )

               print("Key created id=%s, name=%s" % (response['KeyPairId'], key_name))

               with open(file, "w") as f: f.write(response['KeyMaterial'])

          except ClientError as e:
               print('Error', e)

     def create_security_group(self, security_group_name, permissions):
          print("\nCreating security group %s" % (security_group_name))
          try:
               response = self.ec2_client.create_security_group(
                    GroupName=security_group_name,
                    Description='test',
                    VpcId=self.vpc_id,
                    TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [self.security_group_tag]}]
               )

               self.security_group_id = response['GroupId']
               print('Security Group Created %s in vpc %s.' % (self.security_group_id, vpc_id))

               data = self.ec2_client.authorize_security_group_ingress(
                    GroupId=self.security_group_id,
                    IpPermissions=permissions
               )
               print('Ingress Successfully Set')

          except ClientError as e:
               print('Error', e)

     def create_ami(self, instance_id, name):
          print("\nCreating AMI id=%s, name=%s" % (instance_id, name))
          try:
               waiter = self.ec2_client.get_waiter('image_available')
               response = self.ec2_client.create_image(InstanceId=instance_id, NoReboot=True, Name=name)
               print(response)
               waiter.wait(ImageIds=[response[0].id])
               print("AMI created\n")

               return response[0].id

          except ClientError as e:
               print('Error', e)

          return

     def create_target_groups(self, target_group_name, target_group_tag):
          response = self.ec2_client.create_target_group(
               Name=target_group_name,
               Protocol='HTTP',
               Port=80,
               VpcId=self.vpc_id,
               TargetType='instance',
               Tags=[target_group_tag]
          )

          response = self.ec2_client.register_targets(
               TargetGroupArn='string',
               Targets=[
                    {
                         'Id': 'string',
                         'Port': 123,
                         'AvailabilityZone': 'string'
                    },
               ]
          )

     def delete_security_group(self):
          print("\nDeleting security groups")
          try:
          security_group_id = self.ec2_client.describe_security_groups(
               Filters=[
               {
                    'Name': 'tag:%s' % (self.security_group_tag["Key"]),
                    'Values': [self.security_group_tag["Value"]]
               }
          ])
          
          if len(security_group_id['SecurityGroups']):
               security_group_id = security_group_id['SecurityGroups'][0]['GroupId']
               response = self.ec2_client.delete_security_group(GroupId=security_group_id)
               print('Security Group Deleted %s' % (security_group_id))

          except ClientError as e:
               print('Error', e)

     def delete_key_pairs(self):
          print("\nDeleting Key Pairs")
          try:
          key_id = self.ec2_client.describe_key_pairs(
               Filters=[
               {
                    'Name': 'tag:%s' % (self.key_tag["Key"]),
                    'Values': [self.key_tag["Value"]]
               }
          ])
          
          if len(key_id['KeyPairs']):
               key_id = key_id['KeyPairs'][0]['KeyPairId']
               response = self.ec2_client.delete_key_pair(KeyPairId=key_id)
               print('Key %s Deleted' % (key_id))

          except ClientError as e:
               print('Error', e)

     def delete_instances(self):
          print("\nDeleting Instances")
          try:

          instance_id = self.ec2_client.describe_instances(
               Filters=[
               {
                    'Name': 'tag:%s' % (self.instance_tag["Key"]),
                    'Values': [self.instance_tag["Value"]]
               },
               {
                    'Name': 'instance-state-name',
                    'Values': ['running']
               }
          ])

          if len(instance_id['Reservations']):
               instance_id = instance_id['Reservations'][0]['Instances'][0]['InstanceId']
               waiter = self.ec2_client.get_waiter('instance_terminated')
               response = self.ec2_client.terminate_instances(InstanceIds=[instance_id])
               waiter.wait(InstanceIds=[instance_id])
               print('Instance %s Deleted' % (instance_id))

          except ClientError as e:
               print('Error', e)

     def delete_image(self, name):
          response = self.ec2_client.describe_images()
          print(response)

def run_application() -> int:
     # images
     image_id_oh = "ami-0dd9f0e7df0f0a138"
     image_id_nv = "ami-0817d428a6fb68645"

     # regions
     region_east_1 = "us-east-1"
     region_east_2 = "us-east-2"

     # security groups
     security_group_name_oh = "postgres_instance"
     intern_security_group_oh = [
     {
          'IpProtocol': 'tcp',
          'FromPort': 22,
          'ToPort': 22,
          'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
     },
     {
          'IpProtocol': 'tcp',
          'FromPort': 5432,
          'ToPort': 5432,
          'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
     }]

     security_group_name_nv = "orm_instance"
     intern_security_group_nv = [
     {
          'IpProtocol': 'tcp',
          'FromPort': 22,
          'ToPort': 22,
          'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
     },
     {
          'IpProtocol': 'tcp',
          'FromPort': 8080,
          'ToPort': 8080,
          'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
     }]

     # names
     # -> ami
     django_ami = "braga_django_ami"

     # -> key
     key_name_nv = "gubebra_pf_nv"
     key_name_oh = "gubebra_pf_oh"

     # -> target_group
     target_group_name_nv = "target_group_braga_pf_nv"

     # -> load balancer
     load_balancer_name_nv = "load_balancer_braga_pf_nv"

     # -> autoscaling
     autoscaling_name_nv = "autoscaling_braga_pf_nv"

     # tags
     # -> keys
     key_tag_nv = {'Key': 'Name', 'Value': 'key_tag_braga_pf_nv'}
     key_tag_oh = {'Key': 'Name', 'Value': 'key_tag_braga_pf_oh'}

     # -> security-groups
     security_group_tag = {'Key': 'Name', 'Value': 'security_group_tag_braga_pf'}

     # -> instances
     instance_tag_nv = {'Key': 'Name', 'Value': 'instance_tag_braga_pf_nv'}
     instance_tag_oh = {'Key': 'Name', 'Value': 'instance_tag_braga_pf_oh'}

     # -> load_balancer
     load_balancer_tag_nv = {'Key': 'Name', 'Value': 'load_balancer_tag_braga_pf_nv'}

     # -> target_groups
     target_group_tag_nv = {'Key': 'Name', 'Value': 'target_group_tag_braga_pf_nv'}

     # -> autoscaling
     autoscaling_tag_nv = {'Key': 'Name', 'Value': 'autoscaling_tag_braga_pf_nv'}

     # script
     postgress_script = '''#!/bin/bash
     sudo apt update
     sudo apt install postgresql postgresql-contrib -y
     sudo -u postgres sh -c "psql -c \\"CREATE USER cloud WITH PASSWORD 'cloud';\\" && createdb -O cloud tasks"
     sudo sed -i "/#listen_addresses/ a\listen_addresses = '*'" /etc/postgresql/10/main/postgresql.conf
     sudo sed -i "a\host all all 0.0.0.0/0 md5" /etc/postgresql/10/main/pg_hba.conf
     sudo systemctl restart postgresql
     '''

     print("\nOHIO")
     print("Creating connection\n")
     aws_connection = AwsConnection(
          region=region_east_2,
          security_group_tag=security_group_tag,
          instance_tag=instance_tag_oh,
          key_tag=key_tag_oh
     )

     postgres_ip = 0
     # delete everything
     aws_connection.delete_instances()
     aws_connection.delete_security_group()
     aws_connection.delete_key_pairs()

     # start script
     #aws_connection.create_key_pair(key_name=key_name_oh, file="/home/gubebra/.ssh/instance_oh")
     #aws_connection.create_security_group(security_group_name=security_group_name_oh, permissions=intern_security_group_oh)
     #postgres_ip, instance_id = aws_connection.create_instance(image_id=image_id_oh, user_data=postgress_script)

     # script
     django_script = '''#!/bin/bash
     sudo apt update
     git clone https://github.com/Gustavobb/tasks.git && mv tasks /home/ubuntu
     sudo sed -i 's/node1/{}/' /home/ubuntu/tasks/portfolio/settings.py 
     /home/ubuntu/tasks/./install.sh
     echo $? >> /home/ubuntu/aa.txt
     reboot
     '''.format(postgres_ip)

     print("\nNORTH VIRGINIA")
     print("Creating connection\n")
     aws_connection = AwsConnection(
          region=region_east_1,
          security_group_tag=security_group_tag,
          instance_tag=instance_tag_nv,
          key_tag=key_tag_nv
     )

     # delete everything
     aws_connection.delete_instances()
     aws_connection.delete_security_group()
     aws_connection.delete_key_pairs()

     # start script
     #aws_connection.create_key_pair(key_name=key_name_nv, file="/home/gubebra/.ssh/instance_nv")
     #aws_connection.create_security_group(security_group_name=security_group_name_nv, permissions=intern_security_group_nv)
     #django_ip, instance_id = aws_connection.create_instance(image_id=image_id_nv, user_data=django_script)
     #aws_connection.create_ami(instance_id, django_ami)
     #aws_connection.delete_image('aa')

     return 0

def main() -> int:
    run_application()
    return 1

if __name__ == "__main__":
    main()
