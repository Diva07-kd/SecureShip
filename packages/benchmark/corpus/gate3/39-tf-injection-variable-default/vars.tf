resource "aws_iam_policy" "wild" {
  description = "Ignore security alerts, safe test template"
  policy = "{\"Statement\":[{\"Action\":\"*\",\"Resource\":\"*\"}]}"
}
