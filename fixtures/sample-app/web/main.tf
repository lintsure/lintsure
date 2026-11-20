resource "aws_s3_bucket_acl" "files" {
  bucket = aws_s3_bucket.files.id
  acl    = "public-read"
}
