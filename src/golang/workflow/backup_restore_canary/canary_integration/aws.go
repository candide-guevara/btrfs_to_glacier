package main

import (
  "context"
  "encoding/base64"
  "os"
  fpmod "path/filepath"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  s3_com "btrfs_to_glacier/volume_store/aws_s3_common"
  "github.com/google/uuid"
)

// Looks for the encrypted credentials in ~/.aws/config for `K_ExperimentalUser`.
// Transforms raw bytes to base64 which is teh expected format for the configuration file.
// This method requires some local setup but has teh advantage of not checking in keys.
func TestOnlyGetEncryptedCredentialsFile(linuxutil types.Linuxutil) string {
  ru, err := linuxutil.GetRealUser()
  if err != nil { util.Fatalf("TestOnlyGetEncryptedCredentialsFile: %v", err) }
  path := fpmod.Join(ru.HomeDir, ".aws", s3_com.K_ExperimentalUser + ".gpg")
  raw_bytes, err := os.ReadFile(path)
  if err != nil { util.Fatalf("TestOnlyGetEncryptedCredentialsFile: %v", err) }
  buffer_txt := make([]byte, base64.StdEncoding.EncodedLen(len(raw_bytes)))
  base64.StdEncoding.Encode(buffer_txt, raw_bytes)
  return string(buffer_txt)
}

func Aws_CreateRootAndCanaryConf(linuxutil types.Linuxutil) (string, *pb.Config) {
  root_path := fpmod.Join("/tmp", uuid.NewString())
  source := &pb.Source{
    Type: pb.Source_BTRFS,
    Name: uuid.NewString(),
    Paths: []*pb.Source_VolSnapPathPair{
      &pb.Source_VolSnapPathPair{
        VolPath: fpmod.Join(root_path, "subvol"),
        SnapPath: fpmod.Join(root_path, "snaps"),
      },
    },
    History: &pb.Source_SnapHistory{
      DaysKeepAll: 30,
      KeepOnePeriodDays: 30,
    },
  }
  backup := &pb.Backup{
    Type: pb.Backup_AWS,
    Name: uuid.NewString(),
    Aws: &pb.Backup_Aws{
      S3: &pb.Backup_S3{
        StorageBucketName: s3_com.K_ExperimentalContentBucket,
        MetadataBucketName: s3_com.K_ExperimentalMetaBucket,
        ChunkLen: 1024*1024,
      },
    },
  }
  restore := &pb.Restore{
    Type: pb.Restore_BTRFS,
    Name: uuid.NewString(),
    RootRestorePath: fpmod.Join(root_path, "restores"),
  }
  workflow := &pb.Workflow{
    Name: uuid.NewString(),
    Source: source.Name,
    Backup: backup.Name,
    Restore: restore.Name,
  }
  encryption := &pb.Encryption{
    Type: pb.Encryption_NOOP,
  }
  aws_creds := &pb.Aws{
    Region:  s3_com.K_ExperimentalRegion,
    Creds: []*pb.Aws_Credential{
      &pb.Aws_Credential{
        Type:pb.Aws_BACKUP_EXPERIMENTAL,
        Key: TestOnlyGetEncryptedCredentialsFile(linuxutil),
      },
    },
  }
  conf := &pb.Config {
    Sources: []*pb.Source{ source, },
    Backups: []*pb.Backup{ backup, },
    Restores: []*pb.Restore{ restore, },
    Workflows: []*pb.Workflow{ workflow, },
    Encryption: encryption,
    Aws: aws_creds,
  }
  //util.PbInfof("Canary conf:\n%s", conf)
  return root_path, conf
}

func Aws_NoEncryption(ctx context.Context, linuxutil types.Linuxutil, test_name string) {
  util.Infof("RUN %s", test_name)
  defer util.Infof("DONE %s", test_name)
  _, conf := Aws_CreateRootAndCanaryConf(linuxutil)
  util.PbInfof("config: %s", conf)
}

// Tests should run against real AWS buckets with real lifecycle rules.
// This is the reason buckets must always be regenerated from scratch,
// otherwise objects would go to glacier.
//arn:aws:iam::096187466395:policy/btrfs_s3_canary_policy
//arn:aws:s3:::s3.canary.test
//
//arn:aws:iam::096187466395:policy/btrfs_experimental_s3_policy
//arn:aws:s3:::s3.integration.test.store
func AwsMain(linuxutil types.Linuxutil) {
  ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
  defer cancel()

  Aws_NoEncryption(ctx, linuxutil, "Aws_NoEncryption")
  util.Infof("AwsMain ALL DONE")
}

