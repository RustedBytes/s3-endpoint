const {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} = require("@aws-sdk/client-s3");

const endpoint = "http://127.0.0.1:9000";
const bucket = "js-sdk-bucket";
const key = "hello.txt";
const body = Buffer.from("hello from aws sdk js v3\n", "utf8");

async function bodyToBuffer(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function main() {
  const s3 = new S3Client({
    endpoint,
    forcePathStyle: true,
    region: "us-east-1",
    credentials: {
      accessKeyId: "test",
      secretAccessKey: "testsecret",
    },
  });

  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: body,
      ContentType: "text/plain",
      Metadata: {
        owner: "js-sdk",
      },
    }),
  );

  const head = await s3.send(
    new HeadObjectCommand({
      Bucket: bucket,
      Key: key,
    }),
  );
  if (head.ContentLength !== body.length) {
    throw new Error(`unexpected content length: ${head.ContentLength}`);
  }
  if (head.Metadata?.owner !== "js-sdk") {
    throw new Error(`unexpected owner metadata: ${head.Metadata?.owner}`);
  }

  const got = await s3.send(
    new GetObjectCommand({
      Bucket: bucket,
      Key: key,
    }),
  );
  const gotBody = await bodyToBuffer(got.Body);
  if (!gotBody.equals(body)) {
    throw new Error(`unexpected body: ${gotBody.toString("utf8")}`);
  }

  await s3.send(
    new DeleteObjectCommand({
      Bucket: bucket,
      Key: key,
    }),
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
