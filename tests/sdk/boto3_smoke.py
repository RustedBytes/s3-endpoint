import tempfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from boto3.s3.transfer import TransferConfig


ENDPOINT_URL = "http://127.0.0.1:9000"
BUCKET = "sdk-bucket"


def client():
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT_URL,
        aws_access_key_id="test",
        aws_secret_access_key="testsecret",
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def assert_body(s3, key, expected):
    got = s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
    assert got == expected, (key, got, expected)


def put_object_flow(s3):
    body = b"hello from boto3"
    s3.put_object(
        Bucket=BUCKET,
        Key="hello.txt",
        Body=body,
        ContentType="text/plain",
        Metadata={"owner": "sdk"},
    )
    assert_body(s3, "hello.txt", body)
    head = s3.head_object(Bucket=BUCKET, Key="hello.txt")
    assert head["ContentLength"] == len(body)
    assert head["Metadata"]["owner"] == "sdk"


def multipart_flow(s3):
    create = s3.create_multipart_upload(Bucket=BUCKET, Key="multipart.bin")
    upload_id = create["UploadId"]
    try:
        first = b"a" * (5 * 1024 * 1024)
        second = b"final part"
        part1 = s3.upload_part(
            Bucket=BUCKET,
            Key="multipart.bin",
            UploadId=upload_id,
            PartNumber=1,
            Body=first,
        )
        part2 = s3.upload_part(
            Bucket=BUCKET,
            Key="multipart.bin",
            UploadId=upload_id,
            PartNumber=2,
            Body=second,
        )
        listed = s3.list_parts(Bucket=BUCKET, Key="multipart.bin", UploadId=upload_id)
        assert [part["PartNumber"] for part in listed["Parts"]] == [1, 2]
        s3.complete_multipart_upload(
            Bucket=BUCKET,
            Key="multipart.bin",
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [
                    {"PartNumber": 1, "ETag": part1["ETag"]},
                    {"PartNumber": 2, "ETag": part2["ETag"]},
                ]
            },
        )
    except Exception:
        s3.abort_multipart_upload(Bucket=BUCKET, Key="multipart.bin", UploadId=upload_id)
        raise
    assert_body(s3, "multipart.bin", first + second)


def transfer_manager_flow(s3):
    key = "transfer-manager.bin"
    body = (b"transfer manager multipart body\n" * 180000)[:6 * 1024 * 1024]
    config = TransferConfig(
        multipart_threshold=5 * 1024 * 1024,
        multipart_chunksize=5 * 1024 * 1024,
    )
    with tempfile.NamedTemporaryFile() as file:
        file.write(body)
        file.flush()
        s3.upload_file(
            file.name,
            BUCKET,
            key,
            ExtraArgs={"ContentType": "application/octet-stream"},
            Config=config,
        )
    assert_body(s3, key, body)


def delete_flow(s3):
    s3.delete_object(Bucket=BUCKET, Key="hello.txt")
    try:
        s3.head_object(Bucket=BUCKET, Key="hello.txt")
    except ClientError as error:
        if error.response["ResponseMetadata"]["HTTPStatusCode"] == 404:
            return
        raise
    raise AssertionError("deleted object still exists")


def main():
    s3 = client()
    put_object_flow(s3)
    multipart_flow(s3)
    transfer_manager_flow(s3)
    delete_flow(s3)


if __name__ == "__main__":
    main()
