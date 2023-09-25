/*************************************************************
Create an IIS Web App that Connects to SQL RDS
*************************************************************/
/************************************************************/
# Creating a Virtual Private Cloud (VPC) named "hashi_vpc"
resource "aws_vpc" "hashi_vpc" {
  cidr_block           = var.vpc_cidr # Change to your desired VPC CIDR block
  enable_dns_hostnames = true         # You can disable DNS hostnames if not needed
  enable_dns_support   = true         # You can disable DNS support if not needed

  tags = {
    Name = "dev" # Customize the VPC name/tag
  }
}

# Creating a private subnet within the VPC
resource "aws_subnet" "hashi_private_subnet" {
  vpc_id                  = aws_vpc.hashi_vpc.id
  cidr_block              = var.private_subnet_cidr # Change to your desired private subnet CIDR block
  map_public_ip_on_launch = false                   # Set to true if you want instances in this subnet to have public IPs
  availability_zone       = var.availability_zone_a # Change to your desired availability zone

  tags = {
    Name = "dev-private" # Customize the subnet name/tag
  }
}

# Creating another private subnet within the VPC in another availability zone.
resource "aws_subnet" "hashi_private_subnet_b" {
  vpc_id                  = aws_vpc.hashi_vpc.id
  cidr_block              = var.private_subnet_b_cidr # Change to your desired private subnet CIDR block
  map_public_ip_on_launch = false                     # Set to true if you want instances in this subnet to have public IPs
  availability_zone       = var.availability_zone_b   # Change to your desired availability zone

  tags = {
    Name = "dev-private_b" # Customize the subnet name/tag
  }
}

# Creating a public subnet within the VPC
resource "aws_subnet" "hashi_public_subnet" {
  vpc_id                  = aws_vpc.hashi_vpc.id
  cidr_block              = var.public_subnet_cidr  # Change to your desired public subnet CIDR block
  map_public_ip_on_launch = true                    # Set to false if you don't want instances in this subnet to have public IPs
  availability_zone       = var.availability_zone_a # Change to your desired availability zone

  tags = {
    Name = "dev-public" # Customize the subnet name/tag
  }
}

# Creating another public subnet in a different availability zone
resource "aws_subnet" "hashi_public_subnet_2" {
  vpc_id                  = aws_vpc.hashi_vpc.id
  cidr_block              = var.public_subnet_2_cidr # Change to your desired public subnet CIDR block
  map_public_ip_on_launch = true                     # Set to false if you don't want instances in this subnet to have public IPs
  availability_zone       = var.availability_zone_b  # Change to your desired availability zone

  tags = {
    Name = "dev-public-2" # Customize the subnet name/tag
  }
}

# Associating the first public subnet with a route table
resource "aws_route_table_association" "hashi_public_subnet_assoc" {
  subnet_id      = aws_subnet.hashi_public_subnet.id
  route_table_id = aws_route_table.hashi_public_rt.id
}

# Associating the second public subnet with the same route table
resource "aws_route_table_association" "hashi_public_subnet_2_assoc" {
  subnet_id      = aws_subnet.hashi_public_subnet_2.id
  route_table_id = aws_route_table.hashi_public_rt.id
}

# Creating an internet gateway and attaching it to the VPC
resource "aws_internet_gateway" "hashi_internet_gateway" {
  vpc_id = aws_vpc.hashi_vpc.id

  tags = {
    Name = "dev-igw" # Customize the internet gateway name/tag
  }
}

# Creating a public route table for the VPC
resource "aws_route_table" "hashi_public_rt" {
  vpc_id = aws_vpc.hashi_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.hashi_internet_gateway.id
  }

  tags = {
    Name = "dev_public_rt" # Customize the route table name/tag
  }
}

# Allocating an Elastic IP for the NAT gateway
resource "aws_eip" "nat_eip" {
  domain = "vpc"
}

# Creating a NAT gateway within the first public subnet
resource "aws_nat_gateway" "hashi_nat_gateway" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.hashi_public_subnet.id

  tags = {
    Name = "dev-nat" # Customize the NAT gateway name/tag
  }
}

# Creating a private route table for the VPC
resource "aws_route_table" "hashi_private_rt" {
  vpc_id = aws_vpc.hashi_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.hashi_nat_gateway.id
  }

  tags = {
    Name = "dev_private_rt" # Customize the route table name/tag
  }
}

# Associating the private subnet with the private route table
resource "aws_route_table_association" "hashi_private_assoc" {
  subnet_id      = aws_subnet.hashi_private_subnet.id
  route_table_id = aws_route_table.hashi_private_rt.id
}

# Creating a security group for the web server
resource "aws_security_group" "hashi_web_sg" {
  name        = "web-sg"
  description = "Security group for web server"
  vpc_id      = aws_vpc.hashi_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-sg"
  }
}

# Creating a security group for the Application Load Balancer (ALB)
resource "aws_security_group" "hashi_alb_sg" {
  name        = "alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.hashi_vpc.id

  # Allowing incoming traffic on port 80 and 443
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Permitting the ALB to forward traffic to the web server on port 80
resource "aws_security_group_rule" "allow_alb" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.hashi_web_sg.id
  source_security_group_id = aws_security_group.hashi_alb_sg.id
}

# Permitting the ALB to forward traffic to the web server on port 443
resource "aws_security_group_rule" "allow_alb_https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.hashi_web_sg.id
  source_security_group_id = aws_security_group.hashi_alb_sg.id
}

# Creating a security group for the SQL server
resource "aws_security_group" "hashi_sql_sg" {
  name        = "sql_db_sg"
  description = "Security group for SQL server"
  vpc_id      = aws_vpc.hashi_vpc.id

  # Allow incoming SQL traffic only from the web server's security group
  /*
  ingress {
    from_port       = 1433 # SQL Server port
    to_port         = 1433
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id] # Allow incoming traffic only from the web server's security group
  }
*/
  # Other rules as needed

  tags = {
    Name = "sql_db_sg"
  }
}

# Creating an AWS Key Pair for authentication
resource "aws_key_pair" "hashi_auth" {
  key_name   = "hashikey"
  public_key = file("~/.ssh/hashikey.pub") # Provide the path to your public key file
}

# Creating an IAM role for EC2 instances to use Amazon SSM
resource "aws_iam_role" "ssm_role" {
  name = "SSMRoleForEC2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Attaching the SSM policy to the IAM role
resource "aws_iam_role_policy_attachment" "ssm_attach" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
  role       = aws_iam_role.ssm_role.name
}

# Creating an IAM instance profile for EC2 instances
resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "SSMInstanceProfile"
  role = aws_iam_role.ssm_role.name
}

/**********************************************************
# Creating an EC2 instance for the web server
**********************************************************/
resource "aws_instance" "dev_node" {
  instance_type          = var.instance_type          # Change to your desired instance type
  ami                    = data.aws_ami.server_ami.id # Use the appropriate AMI ID
  key_name               = var.key_name               # Change to your SSH key name
  vpc_security_group_ids = [aws_security_group.hashi_web_sg.id]
  subnet_id              = aws_subnet.hashi_private_subnet.id
  iam_instance_profile   = aws_iam_instance_profile.ssm_instance_profile.name

/**********************************************************/
#Web Page user_data

  user_data = <<-EOF
<powershell>
# Logging Function
function Write-Log {
    param (
        [string]$Message,
        [string]$LogFilePath = "C:\terraform_web_setup.log"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fullMessage = "$timestamp : $Message"
    
    Add-Content -Path $LogFilePath -Value $fullMessage
}

Write-Log "Starting the installation of Web-Server feature."
Install-WindowsFeature -name Web-Server -IncludeManagementTools
Write-Log "Web-Server feature installation completed."

# Install SQL Server PowerShell module
Write-Log "Installing SQL Server PowerShell module..."
Install-Module -Name SqlServer -Force -AllowClobber
Write-Log "SQL Server PowerShell module installation completed."

# Get the RDS endpoint from the Terraform output
$rds_endpoint = Invoke-RestMethod -Uri http://169.254.169.254/latest/user-data/rds_endpoint

# Set up database connection parameters
$serverName = $rds_endpoint
$databaseName = var.db_name
$databaseUsername = var.db_username
$db_password = var.db_password
$cred = Get-Credential -UserName $databaseUsername -Password (ConvertTo-SecureString -String $db_password -AsPlainText -Force)

# Create a table for storing data if it doesn't exist
Write-Log "Creating a table for storing data..."
Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName -Credential $cred -Query @"
CREATE TABLE IF NOT EXISTS ThingstoSave (
    ID INT IDENTITY(1,1) PRIMARY KEY,
    Name NVARCHAR(255),
    Description NVARCHAR(1000)
)
"@
Write-Log "Table creation completed."

# Generate HTML content for the web app
$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple Web App</title>
    <style>
        body {
            font-family: Arial, sans-serif;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        table, th, td {
            border: 1px solid #ccc;
        }
        th, td {
            padding: 8px;
            text-align: left;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Simple Web App</h1>
        <h2>Data Table</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                # PowerShell script here to fetch and display data from the SQL database table
                $sqlQuery = "SELECT * FROM YourTable"
                $sqlConnection = New-Object System.Data.SqlClient.SqlConnection
                $sqlConnection.ConnectionString = "Server=$serverName;Database=$databaseName;User Id=$databaseUsername;Password=$db_password"
                $sqlConnection.Open()
                $sqlCommand = $sqlConnection.CreateCommand()
                $sqlCommand.CommandText = $sqlQuery
                $sqlDataReader = $sqlCommand.ExecuteReader()

                while ($sqlDataReader.Read()) {
                    $id = $sqlDataReader["ID"]
                    $name = $sqlDataReader["Name"]
                    $description = $sqlDataReader["Description"]
                    Write-Output "<tr><td>$id</td><td>$name</td><td>$description</td></tr>"
                }

                $sqlDataReader.Close()
                $sqlConnection.Close()
            </tbody>
        </table>
        <h2>Add Data</h2>
        <form action="/add" method="post">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" required><br>
            <label for="description">Description:</label>
            <textarea id="description" name="description" required></textarea><br>
            <input type="submit" value="Add Data">
        </form>
    </div>
</body>
</html>
"@

Start-Service -Name W3SVC

# Write the HTML content to the default IIS folder
Write-Log "Generating the HTML content for the web app."
$htmlContent | Out-File -Encoding ASCII C:\inetpub\wwwroot\index.html
Write-Log "HTML content written to C:\inetpub\wwwroot\index.html successfully."
</powershell>

EOF

  tags = {
    Name = "dev-node" # Customize the instance name/tag
  }

  root_block_device {
    # volume_size = 8  # You can specify the root volume size if needed
  }
}

# Creating an Application Load Balancer (ALB)
resource "aws_lb" "web_alb" {
  name               = "dev-web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.hashi_alb_sg.id]
  subnets            = [aws_subnet.hashi_public_subnet.id, aws_subnet.hashi_public_subnet_2.id]

  enable_deletion_protection       = false
  enable_cross_zone_load_balancing = true
}

# Creating a target group for the ALB
resource "aws_lb_target_group" "web_tg" {
  name     = "dev-web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.hashi_vpc.id

  health_check {
    enabled             = true
    interval            = 30
    path                = "/"
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

# Attaching the EC2 instance to the target group
resource "aws_lb_target_group_attachment" "web_tg_attachment" {
  target_group_arn = aws_lb_target_group.web_tg.arn
  target_id        = aws_instance.dev_node.id
  port             = 80
}

# Creating a listener for the ALB to forward traffic to the target group
resource "aws_lb_listener" "web_listener" {
  load_balancer_arn = aws_lb.web_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}

# Creating a bastion host for SSH access
resource "aws_instance" "bastion" {
  ami           = data.aws_ami.server_ami.id # Change to a suitable Linux/Windows AMI ID
  instance_type = "t2.micro"                 # Change to your desired instance type
  subnet_id     = aws_subnet.hashi_public_subnet.id
  key_name      = aws_key_pair.hashi_auth.key_name

  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  tags = {
    Name = "Bastion" # Customize the bastion host name/tag
  }
}

# Creating a security group for the bastion host
resource "aws_security_group" "bastion_sg" {
  name   = "Bastion-SG"
  vpc_id = aws_vpc.hashi_vpc.id

  ingress {
    from_port   = 22 # Use 3389 for Windows instances using RDP
    to_port     = 22 # Use 3389 for Windows instances using RDP
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # ***Restrict SSH access to a specific IP range for security. # Correspond to the IP address ranges from which you want to allow traffic.
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Bastion-SG"
  }
}

# Creating a subnet group for the database.
resource "aws_db_subnet_group" "db_subnet_group" {
  name = "db_subnet_group"
  subnet_ids = [
    aws_subnet.hashi_private_subnet.id,   # Subnet in Availability Zone A
    aws_subnet.hashi_private_subnet_b.id, # Subnet in Availability Zone B
  ]

  tags = {
    Name = "Database subnet group"
  }
}

/**********************************************************
# Provision RDS SQL Server
**********************************************************/
resource "aws_db_instance" "sql_server" {
  allocated_storage       = var.allocated_storage
  storage_type            = "gp2"
  engine                  = "sqlserver-ex"
  engine_version          = var.engine_version
  instance_class          = var.instance_class
  identifier              = var.db_identifier
  username                = var.db_username
  password                = var.db_password
  db_subnet_group_name    = aws_db_subnet_group.db_subnet_group.name
  backup_retention_period = var.backup_retention_period
  backup_window           = var.backup_window
  skip_final_snapshot     = true
  
  tags = {
    name = "cds-dbs"
  }
}

resource "aws_security_group_rule" "sql_rule" {
  type                     = "ingress"
  from_port                = 1433
  to_port                  = 1433
  protocol                 = "tcp"
  security_group_id        = aws_security_group.hashi_sql_sg.id
  source_security_group_id = aws_security_group.web_sg.id
}

resource "aws_security_group" "web_sg" {
  name   = "web_app_sg"
  vpc_id = aws_vpc.hashi_vpc.id

  # Ingress rules
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] #correspond to the IP address ranges from which you want to allow traffic
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] #correspond to the IP address ranges from which you want to allow traffic
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] #correspond to the IP address ranges from which you want to allow traffic
  }

    ingress {
    from_port       = 1433 # SQL Server port
    to_port         = 1433
    protocol        = "tcp"
    security_groups = [aws_security_group.hashi_sql_sg.id] # Allow incoming traffic only from the web server's security group
    }

  tags = {
    Name = "web_app_sg"
  }
}