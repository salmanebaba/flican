# Static scan fixture only: no resources are provisioned by this test.
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = "flican-fixture-only"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
