package main

import (
  "context"
  "time"

  s3_common "btrfs_to_glacier/volume_store/aws_s3_common"
  "btrfs_to_glacier/util"

  "github.com/aws/aws-sdk-go-v2/service/s3"
  s3_types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type s3MetaAdminTester struct { *s3MetaReadWriteTester }

func (self *s3MetaAdminTester) deleteBucket(ctx context.Context) error {
  bucket := Backup(self.Conf).Aws.S3.MetadataBucketName
  return s3_common.DeleteBucket(ctx, self.Client, bucket)
}

func (self *s3MetaAdminTester) TestS3MetadataSetup(ctx context.Context) {
  bucket := Backup(self.Conf).Aws.S3.MetadataBucketName
  err := self.deleteBucket(ctx)

  if err != nil {
    if !s3_common.IsS3Error(new(s3_types.NoSuchBucket), err) {
      util.Fatalf("%v", err)
    }
    util.Infof("TestS3MetadataSetup '%s' not exist", bucket)
  } else {
    waiter := s3.NewBucketNotExistsWaiter(self.Client)
    wait_rq := &s3.HeadBucketInput{ Bucket: &bucket, }
    err = waiter.Wait(ctx, wait_rq, 30 * time.Second)
    if err != nil { util.Fatalf("%v", err) }
    util.Infof("TestS3MetadataSetup '%s' deleted", bucket)
  }

  done := make(chan bool)
  go func() {
    defer close(done)
    err = self.Metadata.SetupMetadata(ctx)
    if err != nil { util.Fatalf("Metadata.SetupMetadata: %v", err) }
    util.Infof("Bucket '%s' created OK", bucket)

    err = self.Metadata.SetupMetadata(ctx)
    if err != nil { util.Fatalf("Not idempotent %v", err) }
  }()
  select {
    case <-done:
    case <-ctx.Done(): util.Fatalf("Timeout: %v", ctx.Err())
  }
}

