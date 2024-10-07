provider "aws" {
  region = "us-east-1" 
}

resource "aws_iam_role" "cognito_role" {
  name = "cognito_user_pool_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Principal = {
          Service = "cognito-idp.amazonaws.com"
        }
        Effect    = "Allow"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cognito_policy_attachment" {
  role       = aws_iam_role.cognito_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/CognitoUserPool"

  depends_on = [aws_iam_role.cognito_role]
}

resource "aws_cognito_user_pool" "my_user_pool" {
  name = "my-user-pool"

  iam_role = aws_iam_role.cognito_role.arn

  username_attributes = ["email"]

  schema {
    name     = "email"
    required = true
    mutable  = false
    attribute_data_type = "String"
  }
}

resource "aws_cognito_user_pool_client" "my_user_pool_client" {
  name         = "my-user-pool-client"
  user_pool_id = aws_cognito_user_pool.my_user_pool.id

  allowed_oauth_flows       = ["code"]
  allowed_oauth_scopes      = ["phone", "email", "openid", "profile"]
  callback_urls              = ["https://example.com/callback"]
  logout_urls                = ["https://example.com/logout"] 
}

resource "aws_db_instance" "my_db" {
  identifier        = "my-database"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage  = 20
  username          = "myuser" 
  password          = "mypassword" 
  db_name           = "mydatabase"
  skip_final_snapshot = true
  vpc_security_group_ids = [aws_security_group.db_sg.id]
}

resource "aws_security_group" "db_sg" {
  name        = "db_security_group"
  description = "Allow access to RDS database"

  ingress {
    from_port   = 5432
    to_port     = 5432
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
