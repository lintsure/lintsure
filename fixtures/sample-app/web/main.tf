resource "aws_s3_bucket_acl" "files" {
  bucket = aws_s3_bucket.files.id
  acl    = "public-read"
}

# Planted: a public database, SSH open to the world, an allow-all policy and an open function URL.
resource "aws_db_instance" "db" {
  publicly_accessible = true
}
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
data "aws_iam_policy_document" "all" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
resource "aws_lambda_function_url" "open" {
  authorization_type = "NONE"
}
