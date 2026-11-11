resource "aws_iam_policy" "reader" {
  name = "reader"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "s3:GetObject"
      Effect = "Allow"
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}
