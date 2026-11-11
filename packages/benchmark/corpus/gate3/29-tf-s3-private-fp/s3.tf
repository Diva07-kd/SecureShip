resource "aws_s3_bucket" "data" {
  bucket = "company-private-data"
  acl = "private"
}
