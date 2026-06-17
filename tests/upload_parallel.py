import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import boto3
from botocore.config import Config

# 1. Configuration
BUCKET_NAME = "test-bucket"
LOCAL_FOLDER = "./my_local_folder"  # Change to your target directory
MAX_WORKERS = 32

# 2. Initialize S3 Client
s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:9000",
    aws_access_key_id="test",
    aws_secret_access_key="testsecret",
    region_name="us-east-1",
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)


def upload_single_file(file_path, s3_key):
    """Worker function to upload a single file to S3."""
    try:
        with open(file_path, "rb") as f:
            s3.put_object(Bucket=BUCKET_NAME, Key=s3_key, Body=f)
        return f"Successfully uploaded {s3_key}"
    except Exception as e:
        return f"Failed to upload {s3_key}: {str(e)}"


def parallel_upload_folder(folder_path):
    """Gathers files and manages the concurrent execution queue."""
    if not os.path.exists(folder_path):
        print(f"Error: Local folder '{folder_path}' does not exist.")
        return

    # Gather file paths and their intended S3 keys
    tasks = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            # Create a relative S3 key matching the folder structure
            relative_path = os.path.relpath(full_path, folder_path)
            s3_key = relative_path.replace(os.sep, "/")
            tasks.append((full_path, s3_key))

    if not tasks:
        print("No files found to upload.")
        return

    print(f"Starting parallel upload of {len(tasks)} files using {MAX_WORKERS} threads...")

    # Execute uploads in parallel using a thread pool
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all upload jobs to the pool
        futures = {
            executor.submit(upload_single_file, local_path, s3_key): s3_key
            for local_path, s3_key in tasks
        }

        # Process results as they complete
        for future in as_completed(futures):
            result = future.result()
            print(result)


if __name__ == "__main__":
    # Run the parallel process directly
    parallel_upload_folder(LOCAL_FOLDER)

