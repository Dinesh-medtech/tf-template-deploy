provider "aws" {
  region = "us-east-1" # Adjust based on your requirements
}

variable "environment_name" {
  description = "Environment name for the deployment"
  type        = string
}

variable "google_client_id" {
  description = "Google Client ID"
  type        = string
}

variable "google_client_secret" {
  description = "Google Client Secret"
  type        = string
}

variable "linkedin_client_id" {
  description = "LinkedIn Client ID"
  type        = string
}

variable "linkedin_client_secret" {
  description = "LinkedIn Client Secret"
  type        = string
}

# Cognito User Pool
resource "aws_cognito_user_pool" "user_pool" {
  name = "my-app-${var.environment_name}"

  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  auto_verified_attributes = ["email"]
  username_attributes       = ["email"]

  password_policy {
    minimum_length               = 8
    require_lowercase            = true
    require_numbers              = true
    require_symbols              = true
    require_uppercase            = true
    temporary_password_validity_days = 30
  }
}

# Cognito User Pool Resource Server
resource "aws_cognito_resource_server" "resource_server" {
  user_pool_id = aws_cognito_user_pool.user_pool.id
  identifier   = "my-app_api"
  name         = "my-app-${var.environment_name}"

  scope {
    scope_name        = "all"
    scope_description = "All resources"
  }
}

# Cognito User Pool Client for Social Login
resource "aws_cognito_user_pool_client" "user_pool_client1" {
  user_pool_id = aws_cognito_user_pool.user_pool.id
  name         = "my-app-SocialLogin-${var.environment_name}"

  generate_secret = true
  allowed_oauth_flows = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes = [
    "openid",
    "profile",
    "email",
    "aws_cognito_resource_server.resource_server.identifier/all"
  ]

  explicit_auth_flows = ["USER_PASSWORD_AUTH"]

  callback_urls = [
    "http://localhost:3000/dashboard"
  ]

  logout_urls = [
    "http://localhost:3000/login"
  ]

  supported_identity_providers = ["LinkedIn", "Google"]
}

# Cognito User Pool Client for Credential Login
resource "aws_cognito_user_pool_client" "user_pool_client2" {
  user_pool_id = aws_cognito_user_pool.user_pool.id
  name         = "my-app-CredentialLogin-${var.environment_name}"

  generate_secret = false
  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]
}

# Google Identity Provider
resource "aws_cognito_user_pool_identity_provider" "google_identity_provider" {
  user_pool_id = aws_cognito_user_pool.user_pool.id
  provider_name = "Google"
  provider_type = "Google"

  provider_details = {
    client_id     = var.google_client_id
    client_secret = var.google_client_secret
    authorize_scopes = "email"
  }

  attribute_mapping = {
    username = "sub"
    email    = "email"
  }
}

# LinkedIn Identity Provider
resource "aws_cognito_user_pool_identity_provider" "linkedin_identity_provider" {
  user_pool_id = aws_cognito_user_pool.user_pool.id
  provider_name = "LinkedIn"
  provider_type = "OIDC"

  provider_details = {
    attributes_request_method = "GET"  
    authorize_url             = "https://www.linkedin.com/oauth/v2/authorization"
    client_id                 = var.linkedin_client_id
    client_secret             = var.linkedin_client_secret
    oidc_issuer               = "https://www.linkedin.com/oauth"
    authorize_scopes          = "openid profile email"
    token_url                 = "https://www.linkedin.com/oauth/v2/accessToken"
    jwks_uri                  = "https://www.linkedin.com/oauth/openid/jwks"
  }

  attribute_mapping = {
    username = "sub"
    email    = "email"
  }
}

# Create a security group for the RDS cluster
resource "aws_security_group" "db_sg" {
  name        = "aurora_db_security_group"
  description = "Allow access to Aurora DB cluster"

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

# Create the Aurora DB cluster
resource "aws_rds_cluster" "aurora_cluster" {
  cluster_identifier      = "aurora-cluster-demo"
  engine                  = "aurora-postgresql"
  engine_version          = "13.6"
  master_username         = "myadmin"
  master_password         = "mypassword"
  database_name           = "mydatabase"
  backup_retention_period = 7  
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true 
  vpc_security_group_ids  = [aws_security_group.db_sg.id]
}

# Create two Aurora DB cluster instances (Writer and Reader)
resource "aws_rds_cluster_instance" "aurora_instance_writer" {
  identifier              = "aurora-instance"
  cluster_identifier      = aws_rds_cluster.aurora_cluster.id
  instance_class          = "db.r6g.large"
  engine                  = aws_rds_cluster.aurora_cluster.engine
  engine_version          = aws_rds_cluster.aurora_cluster.engine_version
  publicly_accessible     = false
  apply_immediately       = true
}
