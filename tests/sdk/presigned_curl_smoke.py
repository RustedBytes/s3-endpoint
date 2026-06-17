import subprocess
import tempfile
from pathlib import Path

import boto3
from botocore.config import Config


ENDPOINT_URL = "http://127.0.0.1:9000"
BUCKET = "presigned-bucket"
KEY = "curl-upload.txt"


def client():
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT_URL,
        aws_access_key_id="test",
        aws_secret_access_key="testsecret",
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def main():
    s3 = client()
    body = b"uploaded through a boto3 presigned URL using curl\n"
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "body.txt"
        path.write_bytes(body)
        url = s3.generate_presigned_url(
            "put_object",
            Params={"Bucket": BUCKET, "Key": KEY},
            ExpiresIn=300,
            HttpMethod="PUT",
        )
        subprocess.run(
            ["curl", "-fsS", "-X", "PUT", "--data-binary", f"@{path}", url],
            check=True,
        )

    got = s3.get_object(Bucket=BUCKET, Key=KEY)["Body"].read()
    assert got == body, (got, body)


if __name__ == "__main__":
    main()
