import boto3
from botocore.client import Config

# ==============================
# USER CONFIGURATION SECTION
# ==============================
AWS_ACCESS_KEY_ID = ""
AWS_SECRET_ACCESS_KEY = ""
ENDPOINT_URL = "https://us-ord-1.linodeobjects.com"
BUCKET_NAME = ""
OBJECT_KEY = "test-url.txt"
EXPIRE_SECONDS = 86400  # 24 hours
# ==============================

# Initialize S3 client
s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    endpoint_url=ENDPOINT_URL,
    config=Config(signature_version="s3v4"),
)

# Generate presigned URL for PUT
url = s3.generate_presigned_url(
    "put_object",
    Params={"Bucket": BUCKET_NAME, "Key": OBJECT_KEY},
    ExpiresIn=EXPIRE_SECONDS,
)

print("Upload URL:")
print(url)
print()
print("To upload with curl:")
print(f'curl -X PUT -T {OBJECT_KEY} "{url}"')
