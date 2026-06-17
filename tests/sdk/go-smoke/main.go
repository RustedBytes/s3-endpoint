package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	endpointURL = "http://127.0.0.1:9000"
	bucket      = "go-sdk-bucket"
	key         = "hello.txt"
)

func main() {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "testsecret", "")),
	)
	if err != nil {
		log.Fatal(err)
	}

	client := s3.NewFromConfig(cfg, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpointURL)
		options.UsePathStyle = true
	})

	body := []byte("hello from aws sdk go v2\n")
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("text/plain"),
		Metadata: map[string]string{
			"owner": "go-sdk",
		},
	}); err != nil {
		log.Fatal(err)
	}

	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Fatal(err)
	}
	if head.ContentLength == nil || *head.ContentLength != int64(len(body)) {
		log.Fatalf("unexpected content length: %v", head.ContentLength)
	}
	if got := head.Metadata["owner"]; got != "go-sdk" {
		log.Fatalf("unexpected owner metadata: %q", got)
	}

	got, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer got.Body.Close()
	gotBody, err := io.ReadAll(got.Body)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(gotBody, body) {
		log.Fatal(fmt.Errorf("unexpected body: %q", gotBody))
	}

	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}); err != nil {
		log.Fatal(err)
	}
}
