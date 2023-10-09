################################
## AWS Provider Module - Main ##
################################

# AWS Provider
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  access_key = "xxxxxxxx"
  secret_key = "xxx"
  region     = "xxx"
}


###################################
## Virtual Machine Module - Main ##
###################################

# Bootstrapping PowerShell Script
data "template_file" "windows-userdata" {
  template = <<EOF
<powershell>

# Check if the script is running with administrative privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Script is not running with administrative privileges. Restarting with elevated permissions..."
    Start-Sleep -Seconds 2


    # Restart the script with elevated permissions
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $PSCommandPath" -Verb RunAs
    exit
}


# Rename Machine
Rename-Computer -NewName "${var.windows_instance_name}" -Force;

# Set the Windows username and password
Start-Process -Wait -FilePath "net" -ArgumentList "user /add dev myP@ssworD1" -Verb RunAs

# Add the user to the Administrators and RDP group (optional)
Add-LocalGroupMember -Group "Remote Desktop Users” -Member dev
Add-LocalGroupMember -Group "Administrators" -Member dev

# Install IIS
Install-WindowsFeature -name Web-Server -IncludeManagementTools;

# Disable password expiration (optional)
WMIC USERACCOUNT WHERE "Name=Administrator" SET PasswordExpires=FALSE
# Enable RDP (Remote Desktop Protocol) for user (optional)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# Restart machine
shutdown -r -t 10;
</powershell>
EOF
}

#considering you have an existing VPC & Subnet created
data "aws_vpc" "my_vpc" {
  id = "xxxxxx" 
}

data "aws_subnet" "my_subnet"{
    id = "subnet-xxxxx"
}
resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  key_name   = var.key_name
  public_key = tls_private_key.example.public_key_openssh
}


# Create EC2 Instance
resource "aws_instance" "windows-server" {
  ami                         = data.aws_ami.windows-2019.id
  instance_type               = var.windows_instance_type
  subnet_id                   = data.aws_subnet.my_subnet.id
  vpc_security_group_ids      = [aws_security_group.aws-windows-sg.id]
  associate_public_ip_address = var.windows_associate_public_ip_address
  source_dest_check           = false
  key_name                    = aws_key_pair.generated_key.key_name
  user_data                   = data.template_file.windows-userdata.rendered
  
  # root disk
  root_block_device {
    volume_size           = var.windows_root_volume_size
    volume_type           = var.windows_root_volume_type
    delete_on_termination = true
    encrypted             = true
  }

  # extra disk
  ebs_block_device {
    device_name           = "/dev/xvda"
    volume_size           = var.windows_data_volume_size
    volume_type           = var.windows_data_volume_type
    encrypted             = true
    delete_on_termination = true
  }
  
  tags = {
    Name        = "test-terraform-windows-server"
  }
}

# # Create Elastic IP for the EC2 instance
# resource "aws_eip" "windows-eip" {
#   vpc  = true
#   tags = {
#     Name        = "${lower(var.app_name)}-${var.app_environment}-windows-eip"
#     Environment = var.app_environment
#   }
# }

# Associate Elastic IP to Windows Server
# resource "aws_eip_association" "windows-eip-association" {
#   instance_id   = aws_instance.windows-server.id
#   allocation_id = aws_eip.windows-eip.id
# }

# Define the security group for the Windows server
resource "aws_security_group" "aws-windows-sg" {
  name        = "sample-test-windows-sg"
  description = "Allow incoming connections"
  vpc_id      = data.aws_vpc.my_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow incoming HTTP connections"
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow incoming RDP connections"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "sample-test-windows-sg"
  }
}
