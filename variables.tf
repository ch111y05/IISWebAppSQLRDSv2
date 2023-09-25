variable "vpc_cidr" {
  description = "The CIDR block for the VPC."
  default     = "10.123.0.0/16"
}

variable "private_subnet_cidr" {
  description = "The CIDR block for the private subnet."
  default     = "10.123.1.0/24"
}
variable "private_subnet_b_cidr" {
  description = "The CIDR block for the private subnet."
  default     = "10.123.2.0/24"
}

variable "public_subnet_cidr" {
  description = "The CIDR block for the first public subnet."
  default     = "10.123.3.0/24"
}

variable "public_subnet_2_cidr" {
  description = "The CIDR block for the second public subnet."
  default     = "10.123.4.0/24"
}

variable "availability_zone_a" {
  description = "The primary availability zone for subnets."
  default     = "us-west-2a"
}

variable "availability_zone_b" {
  description = "The secondary availability zone for subnets."
  default     = "us-west-2b"
}

variable "key_name" {
  description = "The key name for the EC2 instance."
  default     = "hashikey"
}

variable "instance_type" {
  description = "The instance type for the EC2 instance."
  default     = "t3.micro"
}

variable "ami_owner" {
  description = "The AWS account ID that owns the desired AMI."
  default     = "801119661308"
}

variable "ami_name_filter" {
  description = "The name filter for searching AMIs."
  default     = "Windows_Server-2019-English-Full-Base-*"
}

variable "ami_id" {
  description = "The AMI ID for the EC2 instance."
  type        = string
}

/******************************
SQL Variables
******************************/
variable "instance_class" {
  description = "The instance type of the RDS instance"
  default     = "db.t3.micro"
}

variable "allocated_storage" {
  description = "The allocated storage in gibibytes"
  default     = 20
}

variable "backup_retention_period" {
  description = "The days to retain backups for"
  default     = 7
}

variable "engine_version" {
  description = "The engine version to use"
  default     = "15.00.4316.3.v1"
}

variable "backup_window" {
  description = "When to take db backups"
  default     = "00:00-06:00"
}

variable "db_identifier" {
  description = "The database name."
  type        = string
  default     = "cds-dbs" # Replace with your database name
}

variable "db_name" {
  description = "The database name."
  type        = string
  default     = "cds-dbs" # Replace with your database name
}

variable "db_username" {
  description = "The database username"
  type        = string
  default     = "CDaup" # Replace with your actual database password
}

variable "db_password" {
  description = "The database password"
  type        = string
  default     = "CDsDBs!$2024Z+" # Replace with your actual database password
} 