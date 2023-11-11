package encryption

import (
  "context"
  "fmt"
  "testing"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/aws/aws-sdk-go-v2/aws"
  "github.com/aws/aws-sdk-go-v2/service/sts"
  ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func FixedAwsPwPrompt(utype pb.Aws_UserType) types.PwPromptF {
  return TestOnlyFixedPw
}

type StsClientMock struct {
  Err error
  AccessKeyId string
  Expiration time.Time
  SecretAccessKey string
  SessionToken string
  Calls []*sts.GetSessionTokenInput
}

func NewStsClientMock() *StsClientMock {
  return &StsClientMock{
    Err: nil,
    AccessKeyId: "AccessKeyId",
    Expiration: time.Now().Add(12*time.Hour),
    SecretAccessKey: "SecretAccessKey", 
    SessionToken: "SessionToken",
    Calls: nil,
  }
}

func (self *StsClientMock) GetSessionToken(ctx context.Context,
  input *sts.GetSessionTokenInput, opts ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error) {
  self.Calls = append(self.Calls, input)
  rs := &sts.GetSessionTokenOutput{
    Credentials: &ststypes.Credentials{
      AccessKeyId: &self.AccessKeyId,
      Expiration: &self.Expiration,
      SecretAccessKey: &self.SecretAccessKey,
      SessionToken: &self.SessionToken,
    },
  }
  return rs, self.Err
}

func (self *StsClientMock) ExpectCreds() *aws.Credentials {
  return &aws.Credentials{
    AccessKeyID: self.AccessKeyId,
    SecretAccessKey: self.SecretAccessKey,
    SessionToken: self.SessionToken,
    Expires: self.Expiration,
    CanExpire: true,
  }
}

func NewSessionTokenKeyring_ForTest(fixed_input string) (*SessionTokenKeyring, *StsClientMock) {
  sts_client := NewStsClientMock()
  client_builder := func(cfg types.AwsConf) StsClientIf {
    return sts_client
  }
  input_prompt := func(string) (types.SecretString, error) {
    return types.SecretString{fixed_input}, nil
  }
  return NewSessionTokenKeyringHelper(client_builder, FixedAwsPwPrompt, input_prompt), sts_client
}

func LoadTestConfWithKeys(access_key string, secret_key string) *pb.Config {
  key, _ := TestOnlyFixedPw()
  plain := types.SecretString{fmt.Sprintf(`{
    "Version": 1,
    "AccessKeyId": "%s",
    "SecretAccessKey": "%s"
  }`, access_key, secret_key)}
  obfus := AesEncryptString(key, plain)
  aws_creds := &pb.Aws_Credential{
    Type: pb.Aws_BACKUP_WRITER,
    Key: obfus.S,
  }
  conf := &pb.Config {
    Aws: &pb.Aws {
      Creds: []*pb.Aws_Credential{ aws_creds, },
      Region: "eu-central-1", // needs to be valid for unittests
    },
  }
  return conf
}

func LoadTestConf() *pb.Config {
  return LoadTestConfWithKeys("XXX", "YYY")
}

func TestPermAwsCredFromConf(t *testing.T) {
  const access_key = "XXX"
  const secret_key = "XXX"
  conf := LoadTestConfWithKeys(access_key, secret_key)
  aws_creds, err := permAwsCredFromConf(TestOnlyFixedPw, conf.Aws.Creds[0])
  expect_creds := aws.Credentials{
    AccessKeyID: access_key,
    SecretAccessKey: secret_key,
  }
  if err != nil { t.Fatalf("permAwsCredFromConf: %v", err) }
  util.EqualsOrFailTest(t, "Bad unmarshalled creds", aws_creds, expect_creds)
}

func TestGetSessionTokenFor_NoCachedCreds(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  conf := LoadTestConf()
  keyring, sts_client := NewSessionTokenKeyring_ForTest("")
  aws_creds, err := keyring.GetSessionTokenFor(ctx, conf, conf.Aws.Creds[0])
  if err != nil { t.Fatalf("GetSessionTokenFor: %v", err) }
  util.EqualsOrFailTest(t, "Bad sts calls", len(sts_client.Calls), 1)
  util.EqualsOrFailTest(t, "Bad temp creds", aws_creds, sts_client.ExpectCreds())
}

func TestGetSessionTokenFor_ReUseFreshCreds(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  conf := LoadTestConf()
  keyring, sts_client := NewSessionTokenKeyring_ForTest("")
  _, err := keyring.GetSessionTokenFor(ctx, conf, conf.Aws.Creds[0])
  if err != nil { t.Fatalf("GetSessionTokenFor: %v", err) }
  _, err = keyring.GetSessionTokenFor(ctx, conf, conf.Aws.Creds[0])
  if err != nil { t.Fatalf("GetSessionTokenFor: %v", err) }
  util.EqualsOrFailTest(t, "Bad sts calls", len(sts_client.Calls), 1)
}

func TestGetSessionTokenFor_RefreshCredWhenOld(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  conf := LoadTestConf()
  keyring, sts_client := NewSessionTokenKeyring_ForTest("")
  sts_client.Expiration = time.Now().Add(time.Second)
  _, err := keyring.GetSessionTokenFor(ctx, conf, conf.Aws.Creds[0])
  if err != nil { t.Fatalf("GetSessionTokenFor: %v", err) }
  _, err = keyring.GetSessionTokenFor(ctx, conf, conf.Aws.Creds[0])
  if err != nil { t.Fatalf("GetSessionTokenFor: %v", err) }
  util.EqualsOrFailTest(t, "Bad sts calls", len(sts_client.Calls), 2)
}

func TestNewAwsConfigFromTempCreds(t *testing.T) {
  ctx,cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  conf := LoadTestConf()
  keyring, sts_client := NewSessionTokenKeyring_ForTest("")
  globalKeyring = *keyring
  aws_conf, err := NewAwsConfigFromTempCreds(ctx, conf, pb.Aws_BACKUP_WRITER)
  if err != nil { t.Fatalf("NewAwsConfigFromTempCreds: %v", err) }
  aws_creds, err := aws_conf.C.Credentials.Retrieve(ctx)
  if err != nil { t.Fatalf("aws_conf.Credentials.Retrieve: %v", err) }
  util.EqualsOrFailTest(t, "Bad temp creds",
                        aws_creds.SessionToken, sts_client.ExpectCreds().SessionToken)
}

func TestEncryptAwsCreds(t *testing.T) {
  const fixed_input = "some_input"
  keyring, _ := NewSessionTokenKeyring_ForTest(fixed_input)
  encrypt_creds, err := keyring.EncryptAwsCreds(pb.Aws_BACKUP_READER)
  if err != nil { t.Fatalf("EncryptAwsCreds: %v", err) }

  plain_creds, err := permAwsCredFromConf(TestOnlyFixedPw, encrypt_creds)
  if err != nil { t.Fatalf("permAwsCredFromConf: %v", err) }
  expect_creds := aws.Credentials{
    AccessKeyID: fixed_input,
    SecretAccessKey: fixed_input,
  }
  util.EqualsOrFailTest(t, "Bad encrypted creds", plain_creds, expect_creds)
}

