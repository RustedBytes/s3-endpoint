package dev.rustedbytes.s3endpoint;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

public final class Smoke {
    private static final URI ENDPOINT = URI.create("http://127.0.0.1:9000");
    private static final String BUCKET = "java-sdk-bucket";
    private static final String KEY = "hello.txt";

    private Smoke() {}

    public static void main(String[] args) {
        byte[] body = "hello from aws sdk java v2\n".getBytes(StandardCharsets.UTF_8);

        try (S3Client s3 = S3Client.builder()
                .endpointOverride(ENDPOINT)
                .region(Region.US_EAST_1)
                .credentialsProvider(
                        StaticCredentialsProvider.create(
                                AwsBasicCredentials.create("test", "testsecret")))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .serviceConfiguration(
                        S3Configuration.builder()
                                .pathStyleAccessEnabled(true)
                                .build())
                .build()) {
            s3.putObject(
                    PutObjectRequest.builder()
                            .bucket(BUCKET)
                            .key(KEY)
                            .contentType("text/plain")
                            .metadata(Collections.singletonMap("owner", "java-sdk"))
                            .build(),
                    RequestBody.fromBytes(body));

            HeadObjectResponse head = s3.headObject(
                    HeadObjectRequest.builder()
                            .bucket(BUCKET)
                            .key(KEY)
                            .build());
            if (head.contentLength() != body.length) {
                throw new IllegalStateException(
                        "unexpected content length: " + head.contentLength());
            }
            String owner = head.metadata().get("owner");
            if (!"java-sdk".equals(owner)) {
                throw new IllegalStateException("unexpected owner metadata: " + owner);
            }

            ResponseBytes<GetObjectResponse> got = s3.getObject(
                    GetObjectRequest.builder()
                            .bucket(BUCKET)
                            .key(KEY)
                            .build(),
                    ResponseTransformer.toBytes());
            byte[] gotBody = got.asByteArray();
            if (!java.util.Arrays.equals(gotBody, body)) {
                throw new IllegalStateException(
                        "unexpected body: " + new String(gotBody, StandardCharsets.UTF_8));
            }

            s3.deleteObject(
                    DeleteObjectRequest.builder()
                            .bucket(BUCKET)
                            .key(KEY)
                            .build());
        }
    }
}
