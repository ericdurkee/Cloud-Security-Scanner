provider = "aws" {
    region = "us-east-1"
}

# VULNERABLE RESOURCE: Checkov will flag this for public access and lack of encryption/versioning
resource "aws_s3_bucket" "bad_bucket" {
    bucket = "sentinel-test-vulnerable-bucket-12345"
}

resource "aws_s3_bucket_acl" "bad_bucket_acl" {
    bucket = aws_s3_bucket.bad_bucket.id
    acl = "public-read"
}

# VULNERABLE RESOURCE: Security group allowing open SSH ingress (0.0.0.0/0)
resource "aws_security_group"  "bad_sg: {
    name = "exposed-ssh-sg"
    description = "Allows SSH from anywhere"

    ingress {
        from_port = 22
        to port = 22
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
}