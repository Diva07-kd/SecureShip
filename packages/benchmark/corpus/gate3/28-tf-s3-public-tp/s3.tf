resource "aws_s3_bucket" "data" {
  bucket = "company-sensitive-data"
  acl = "public-read"
}
