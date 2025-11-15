# Automated C2 Infrastructure Deployment
# =====================================
# 
# This Terraform configuration demonstrates automated deployment of
# Command and Control (C2) infrastructure for red team exercises.
# 
# Architecture:
# - C2 Server (Covenant/Sliver)
# - HTTPS Redirector
# - DNS Redirector
# - Monitoring and Logging
#
# Author: Manus AI
# Purpose: Educational demonstration of automated C2 deployment

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment_name" {
  description = "Name for this C2 environment"
  type        = string
  default     = "redteam-exercise"
}

variable "operator_ip" {
  description = "IP address of the red team operator"
  type        = string
}

variable "domain_name" {
  description = "Domain name for C2 operations"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

# Provider configuration
provider "aws" {
  region = var.aws_region
}

# Random password generation
resource "random_password" "c2_admin_password" {
  length  = 16
  special = true
}

# Generate SSH key pair
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "c2_key_pair" {
  key_name   = "${var.environment_name}-key"
  public_key = tls_private_key.ssh_key.public_key_openssh
}

# VPC and Networking
resource "aws_vpc" "c2_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment_name}-vpc"
    Environment = var.environment_name
  }
}

resource "aws_internet_gateway" "c2_igw" {
  vpc_id = aws_vpc.c2_vpc.id

  tags = {
    Name        = "${var.environment_name}-igw"
    Environment = var.environment_name
  }
}

resource "aws_subnet" "c2_public_subnet" {
  vpc_id                  = aws_vpc.c2_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.environment_name}-public-subnet"
    Environment = var.environment_name
  }
}

resource "aws_route_table" "c2_public_rt" {
  vpc_id = aws_vpc.c2_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.c2_igw.id
  }

  tags = {
    Name        = "${var.environment_name}-public-rt"
    Environment = var.environment_name
  }
}

resource "aws_route_table_association" "c2_public_rta" {
  subnet_id      = aws_subnet.c2_public_subnet.id
  route_table_id = aws_route_table.c2_public_rt.id
}

# Security Groups
resource "aws_security_group" "c2_server_sg" {
  name_prefix = "${var.environment_name}-c2-server-"
  vpc_id      = aws_vpc.c2_vpc.id

  # SSH access from operator
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.operator_ip}/32"]
  }

  # C2 listener ports (internal only)
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.redirector_sg.id]
  }

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.redirector_sg.id]
  }

  # Web interface (restricted)
  ingress {
    from_port   = 7443
    to_port     = 7443
    protocol    = "tcp"
    cidr_blocks = ["${var.operator_ip}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment_name}-c2-server-sg"
    Environment = var.environment_name
  }
}

resource "aws_security_group" "redirector_sg" {
  name_prefix = "${var.environment_name}-redirector-"
  vpc_id      = aws_vpc.c2_vpc.id

  # SSH access from operator
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.operator_ip}/32"]
  }

  # HTTPS traffic from internet
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP traffic from internet
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # DNS traffic
  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment_name}-redirector-sg"
    Environment = var.environment_name
  }
}

# User data scripts
locals {
  c2_server_userdata = base64encode(templatefile("${path.module}/scripts/c2_server_setup.sh", {
    admin_password = random_password.c2_admin_password.result
    domain_name    = var.domain_name
  }))

  https_redirector_userdata = base64encode(templatefile("${path.module}/scripts/https_redirector_setup.sh", {
    c2_server_ip = aws_instance.c2_server.private_ip
    domain_name  = var.domain_name
  }))

  dns_redirector_userdata = base64encode(templatefile("${path.module}/scripts/dns_redirector_setup.sh", {
    c2_server_ip = aws_instance.c2_server.private_ip
    domain_name  = var.domain_name
  }))
}

# C2 Server Instance
resource "aws_instance" "c2_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.c2_key_pair.key_name
  vpc_security_group_ids = [aws_security_group.c2_server_sg.id]
  subnet_id              = aws_subnet.c2_public_subnet.id
  user_data              = local.c2_server_userdata

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  tags = {
    Name        = "${var.environment_name}-c2-server"
    Environment = var.environment_name
    Role        = "c2-server"
  }
}

# HTTPS Redirector Instance
resource "aws_instance" "https_redirector" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.small"
  key_name               = aws_key_pair.c2_key_pair.key_name
  vpc_security_group_ids = [aws_security_group.redirector_sg.id]
  subnet_id              = aws_subnet.c2_public_subnet.id
  user_data              = local.https_redirector_userdata

  depends_on = [aws_instance.c2_server]

  tags = {
    Name        = "${var.environment_name}-https-redirector"
    Environment = var.environment_name
    Role        = "https-redirector"
  }
}

# DNS Redirector Instance
resource "aws_instance" "dns_redirector" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.small"
  key_name               = aws_key_pair.c2_key_pair.key_name
  vpc_security_group_ids = [aws_security_group.redirector_sg.id]
  subnet_id              = aws_subnet.c2_public_subnet.id
  user_data              = local.dns_redirector_userdata

  depends_on = [aws_instance.c2_server]

  tags = {
    Name        = "${var.environment_name}-dns-redirector"
    Environment = var.environment_name
    Role        = "dns-redirector"
  }
}

# Data source for Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Elastic IPs for stable addressing
resource "aws_eip" "https_redirector_eip" {
  instance = aws_instance.https_redirector.id
  domain   = "vpc"

  tags = {
    Name        = "${var.environment_name}-https-redirector-eip"
    Environment = var.environment_name
  }
}

resource "aws_eip" "dns_redirector_eip" {
  instance = aws_instance.dns_redirector.id
  domain   = "vpc"

  tags = {
    Name        = "${var.environment_name}-dns-redirector-eip"
    Environment = var.environment_name
  }
}

# CloudWatch Log Groups for monitoring
resource "aws_cloudwatch_log_group" "c2_logs" {
  name              = "/aws/ec2/${var.environment_name}/c2-server"
  retention_in_days = 7

  tags = {
    Environment = var.environment_name
  }
}

resource "aws_cloudwatch_log_group" "redirector_logs" {
  name              = "/aws/ec2/${var.environment_name}/redirectors"
  retention_in_days = 7

  tags = {
    Environment = var.environment_name
  }
}

# S3 Bucket for logs and artifacts
resource "aws_s3_bucket" "c2_artifacts" {
  bucket = "${var.environment_name}-c2-artifacts-${random_password.c2_admin_password.id}"

  tags = {
    Name        = "${var.environment_name}-c2-artifacts"
    Environment = var.environment_name
  }
}

resource "aws_s3_bucket_versioning" "c2_artifacts_versioning" {
  bucket = aws_s3_bucket.c2_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "c2_artifacts_encryption" {
  bucket = aws_s3_bucket.c2_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Outputs
output "c2_server_private_ip" {
  description = "Private IP of the C2 server"
  value       = aws_instance.c2_server.private_ip
}

output "https_redirector_public_ip" {
  description = "Public IP of the HTTPS redirector"
  value       = aws_eip.https_redirector_eip.public_ip
}

output "dns_redirector_public_ip" {
  description = "Public IP of the DNS redirector"
  value       = aws_eip.dns_redirector_eip.public_ip
}

output "c2_admin_password" {
  description = "Admin password for C2 server"
  value       = random_password.c2_admin_password.result
  sensitive   = true
}

output "ssh_private_key" {
  description = "SSH private key for accessing instances"
  value       = tls_private_key.ssh_key.private_key_pem
  sensitive   = true
}

output "s3_bucket_name" {
  description = "S3 bucket for storing artifacts"
  value       = aws_s3_bucket.c2_artifacts.bucket
}

output "deployment_summary" {
  description = "Summary of deployed infrastructure"
  value = {
    environment_name = var.environment_name
    region          = var.aws_region
    c2_server       = aws_instance.c2_server.id
    https_redirector = aws_instance.https_redirector.id
    dns_redirector  = aws_instance.dns_redirector.id
    vpc_id          = aws_vpc.c2_vpc.id
  }
}

