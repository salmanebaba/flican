# Intentionally vulnerable static fixture for Checkov; scanning provisions nothing.
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = "flican-fixture-only"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
