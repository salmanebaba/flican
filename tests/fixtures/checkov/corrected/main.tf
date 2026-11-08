# Static scan fixture only: no resources are provisioned by this test.
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = "flican-fixture-only"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
