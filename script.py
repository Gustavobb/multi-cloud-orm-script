import boto3
import time
from botocore.exceptions import ClientError

class AwsConnection:

     def __init__(self, region, security_group_tag, instance_tag, key_tag):
          self.ec2_resource = boto3.resource('ec2', region_name = region)
          self.ec2_client = boto3.client('ec2', region_name = region)
          self.elvb2_client = boto3.client('elbv2', region_name = region)
          self.elb_client = boto3.client('elb', region_name = region)
          self.autoscaling_client = boto3.client('autoscaling')
          self.security_group_tag = security_group_tag
          self.instance_tag = instance_tag
          self.key_tag = key_tag
          self.key_name = None
          self.security_group_id = None
          self.image_id = None
          self.instance_id = None
          self.vpc_id = self.ec2_client.describe_vpcs().get('Vpcs', [{}])[0].get('VpcId', '')
          self.subnets = [subnet['SubnetId'] for subnet in self.ec2_client.describe_subnets()['Subnets']]
          self.availability_zones = [zone['ZoneName'] for zone in self.ec2_client.describe_availability_zones()['AvailabilityZones']]

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

               self.instance_id = instance[0].id

               return public_ip

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
                    Description='pf_security_group',
                    VpcId=self.vpc_id,
                    TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [self.security_group_tag]}]
               )

               self.security_group_id = response['GroupId']
               print('Security Group Created %s in vpc %s.' % (self.security_group_id, self.vpc_id))

               data = self.ec2_client.authorize_security_group_ingress(
                    GroupId=self.security_group_id,
                    IpPermissions=permissions
               )
               print('Ingress Successfully Set')

               return self.security_group_id

          except ClientError as e:
               print('Error', e)
          
          return

     def create_ami(self, name):
          print("\nCreating AMI id=%s, name=%s" % (self.instance_id, name))
          try:
               waiter = self.ec2_client.get_waiter('image_available')
               response = self.ec2_client.create_image(InstanceId=self.instance_id, NoReboot=True, Name=name)
               waiter.wait(ImageIds=[response["ImageId"]])
               print("AMI created")

               self.image_id = response["ImageId"]

          except ClientError as e:
               print('Error', e)
               
          return

     def create_target_groups(self, target_group_name, target_group_tag):
          print("\nCreating target_group name=%s, instance_id=%s" % (target_group_name, self.instance_id))
          try:
               target_group_arn = self.elvb2_client.create_target_group(
                    Name=target_group_name,
                    Protocol='HTTP',
                    Port=80,
                    VpcId=self.vpc_id,
                    TargetType='instance',
                    Tags=[target_group_tag]
               )['TargetGroups'][0]['TargetGroupArn']

               response = self.elvb2_client.register_targets(
                    TargetGroupArn=target_group_arn,
                    Targets=[
                         {
                              'Id': self.instance_id,
                              'Port': 8080,
                         },
                    ]
               )

               print("target_group created arn=%s and targets created as well" % (target_group_arn))
               return target_group_arn

          except ClientError as e:
               print('Error', e)
          
          return

     def create_load_balancer_v2(self, name, security_group, tag):
          print("\nCreating load_balancer name=%s" % (name))
          try:
               waiter = self.elvb2_client.get_waiter('load_balancer_available')
               load_balancer_arn = self.elvb2_client.create_load_balancer(
                    Name=name,
                    Subnets=self.subnets,
                    Tags=[tag],
                    Type='classic',
               )['LoadBalancers'][0]['LoadBalancerArn']

               waiter.wait(LoadBalancerArns=[load_balancer_arn])
               response = self.elvb2_client.create_listener(
                    DefaultActions=[{'TargetGroupArn': tg_arn, 'Type': 'forward'}],
                    LoadBalancerArn=load_balancer_arn,
                    Port=80,
                    Protocol='HTTP',
               )
               print("load_balancer arn=%s created" % (load_balancer_arn))

          except ClientError as e:
               print('Error', e)

     def create_load_balancer(self, name, security_group, tag):
          print("\nCreating load_balancer name=%s" % (name))
          try:
               load_balancer = self.elb_client.create_load_balancer(
                    LoadBalancerName=name,
                    Listeners=[
                         {
                              'Protocol': 'HTTP',
                              'LoadBalancerPort': 8080,
                              'InstancePort': 8080,
                         },
                    ],
                    Subnets=self.subnets,
                    SecurityGroups=[self.security_group_id],
                    Tags=[
                         {
                              'Key': 'string',
                              'Value': 'string'
                         },
                    ]
               )

               with open("loadbalancer_DNS", "w+") as f: f.write(load_balancer['DNSName'])

               ok = False
               while not ok:
                    lb = self.elb_client.describe_load_balancers()['LoadBalancerDescriptions']
                    for l in lb:
                         if l['LoadBalancerName'] == name: ok = True

                    self.get_timer(time_s=10)

               print("load_balancer created")

          except ClientError as e:
               print('Error', e)

     def create_launch_configuration(self, name):
          print("\nCreating launch_configuration name=%s, key=%s, security_group_id=%s, image_id=%s" % (name, self.key_name, self.security_group_id, self.image_id))
          try:
               response = self.autoscaling_client.create_launch_configuration(
                    LaunchConfigurationName=name,
                    ImageId=self.image_id,
                    KeyName=self.key_name,
                    SecurityGroups=[self.security_group_id],
                    InstanceType='t2.micro',
                    InstanceMonitoring={'Enabled': True},
               )

               print("launch_configuration created")

          except ClientError as e:
               print('Error', e)
     
     def create_autoscaling(self, name, launch_configuration_name, load_balancer_name):
          print("\nCreating autoscaling name=%s, launch_configuration_name=%s" % (name, launch_configuration_name))
          try:
               response = self.autoscaling_client.create_auto_scaling_group(
                    AutoScalingGroupName=name,
                    LaunchConfigurationName=launch_configuration_name,
                    MinSize=2,
                    MaxSize=3,
                    LoadBalancerNames=[load_balancer_name],
                    DesiredCapacity=2,
                    AvailabilityZones=self.availability_zones,
               )

               while not len(self.autoscaling_client.describe_auto_scaling_groups(AutoScalingGroupNames=[name])['AutoScalingGroups']):
                    self.get_timer(time_s=10)

               print("autoscaling created")

          except ClientError as e:
               print('Error', e)

     def delete_autoscaling(self, name):
          print("\nDeleting autoscaling name=%s" % (name))
          try:
               if len(self.autoscaling_client.describe_auto_scaling_groups(AutoScalingGroupNames=[name])['AutoScalingGroups']):
                    response = self.autoscaling_client.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)

                    while len(self.autoscaling_client.describe_auto_scaling_groups(AutoScalingGroupNames=[name])['AutoScalingGroups']):
                         self.get_timer(time_s=10)

                    print("autoscaling deleted")

          except ClientError as e:
               print('Error', e)

     def delete_launch_configuration(self, name):
          print("\nDeleting launch_configuration name=%s" % (name))
          try:
               if len(self.autoscaling_client.describe_launch_configurations(LaunchConfigurationNames=[name])['LaunchConfigurations']):
                    response = self.autoscaling_client.delete_launch_configuration(LaunchConfigurationName=name)
                    print("launch_configuration deleted")

          except ClientError as e:
               print('Error', e)

     def delete_load_balancers_v2(self, name):
          print("\nDeleting load_balancer name=%s" % (name))
          try:
               load_balancers = self.elvb2_client.describe_load_balancers()['LoadBalancers']
               exists = False

               for lb in load_balancers:
                    if lb['LoadBalancerName'] == name: 
                         load_balancer_arn = lb['LoadBalancerArn']
                         exists = True

               if exists:
                    waiter = self.elvb2_client.get_waiter('load_balancers_deleted')
                    response = self.elvb2_client.delete_load_balancer(LoadBalancerArn=load_balancer_arn)
                    waiter.wait(LoadBalancerArns=[load_balancer_arn])
                    print("load_balancer deleted")

          except ClientError as e:
               print('Error', e)

     def delete_load_balancers(self, name):
          print("\nDeleting load_balancer name=%s" % (name))
          try:
               load_balancers = self.elb_client.describe_load_balancers()['LoadBalancerDescriptions']
               exists = False

               for lb in load_balancers:
                    if lb['LoadBalancerName'] == name: exists = True

               if exists:
                    response = self.elb_client.delete_load_balancer(LoadBalancerName=name)
                    ok = True
                    while ok:
                         lb = self.elb_client.describe_load_balancers()['LoadBalancerDescriptions']
                         ok = True
                         if not len(lb): ok = False
                         for l in lb:
                              print(l['LoadBalancerName'])
                              if l['LoadBalancerName'] == name: ok = False

                         self.get_timer(time_s=10)

                    print("load_balancer deleted")

          except ClientError as e:
               print('Error', e)

     def delete_target_groups(self, name):
          print("\nDeleting target groups")
          try:
               target_groups = self.elvb2_client.describe_target_groups()['TargetGroups']
               
               exists = False

               for tg in target_groups:
                    if tg['TargetGroupName'] == name: 
                         target_group_arn = tg['TargetGroupArn']
                         exists = True

               if exists:
                    response = self.elvb2_client.delete_target_group(TargetGroupArn=target_group_arn)
                    print("Target group %s deleted" % (name))

          except ClientError as e:
               print('Error', e)

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
                    while True:
                         try:
                              response = self.ec2_client.delete_security_group(GroupId=security_group_id)
                              break

                         except ClientError as e:
                              self.get_timer(10)

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
          print("\nDeleting Images")
          try:
               image_id = self.ec2_client.describe_images(
               Filters=[{
                         'Name': 'name',
                         'Values': [name]
                    }]
               )

               if len(image_id["Images"]):
                    image_id = image_id["Images"][0]["ImageId"]
                    response = self.ec2_client.deregister_image(ImageId=image_id)
                    print("Image %s deleted" % (response['ResponseMetadata']['RequestId']))
          
          except ClientError as e:
               print('Error', e)

     def get_timer(self, time_s):
          t0 = time.time()
          t1 = time.time()
          while t1 - t0 <= time_s: t1 = time.time()

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
     django_ami = "braga_django_ami_pf"

     # -> key
     key_name_nv = "gubebra_pf_nv"
     key_name_oh = "gubebra_pf_oh"

     # -> target_group
     target_group_name_nv = "braga-pf-nv"

     # -> load balancer
     load_balancer_name_nv = "lb-braga-pf-nv"

     # -> autoscaling
     autoscaling_name_nv = "autoscaling_braga_pf_nv"

     # -> launch configurations
     launch_configurations_name_nv = "launch_configurations_braga_pf_nv"

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
     postgres_ip = 0
     print("\nOHIO")
     print("Creating connection\n")
     aws_connection = AwsConnection(
          region=region_east_2,
          security_group_tag=security_group_tag,
          instance_tag=instance_tag_oh,
          key_tag=key_tag_oh
     )

     # delete everything
     aws_connection.delete_instances()
     aws_connection.delete_security_group()
     aws_connection.delete_key_pairs()

     # start script
     aws_connection.create_key_pair(key_name=key_name_oh, file="/home/gubebra/.ssh/instance_oh")
     aws_connection.create_security_group(security_group_name=security_group_name_oh, permissions=intern_security_group_oh)
     postgres_ip = aws_connection.create_instance(image_id=image_id_oh, user_data=postgress_script)

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
     aws_connection.delete_autoscaling(autoscaling_name_nv)
     aws_connection.delete_load_balancers(load_balancer_name_nv)
     aws_connection.delete_launch_configuration(name=launch_configurations_name_nv)
     aws_connection.delete_image(name=django_ami)
     aws_connection.delete_instances()
     aws_connection.delete_security_group()
     aws_connection.delete_key_pairs()

     # start script
     aws_connection.create_key_pair(key_name=key_name_nv, file="/home/gubebra/.ssh/instance_nv")
     aws_connection.create_security_group(security_group_name=security_group_name_nv, permissions=intern_security_group_nv)
     _django_ip = aws_connection.create_instance(image_id=image_id_nv, user_data=django_script)
     aws_connection.create_ami(name=django_ami)
     aws_connection.delete_instances()
     aws_connection.create_load_balancer(name=load_balancer_name_nv, security_group=security_group_name_nv, tag=load_balancer_tag_nv)
     aws_connection.create_launch_configuration(name=launch_configurations_name_nv)
     aws_connection.create_autoscaling(name=autoscaling_name_nv, launch_configuration_name=launch_configurations_name_nv, load_balancer_name=load_balancer_name_nv)

     return 0

def main() -> int:
    run_application()
    return 1

if __name__ == "__main__":
    main()
