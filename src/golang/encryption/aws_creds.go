package encryption

import (
  "context"
  "encoding/json"
  "fmt"
  "sync"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/aws/aws-sdk-go-v2/aws"
  "github.com/aws/aws-sdk-go-v2/config"
  "github.com/aws/aws-sdk-go-v2/credentials"
  "github.com/aws/aws-sdk-go-v2/service/sts"
)

type StsClientIf interface {
  GetSessionToken(context.Context,
    *sts.GetSessionTokenInput, ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error)
}
type StsClientBuilderF = func(aws.Config) StsClientIf

type SessionTokenKeyring struct {
  Mutex   *sync.Mutex
  Keyring map[pb.Aws_UserType]aws.Credentials
  PwPrompt         func(pb.Aws_UserType) types.PwPromptF
  StsClientBuilder StsClientBuilderF
  Duration         time.Duration
  RefreshThreshold time.Duration
}
var globalKeyring SessionTokenKeyring

func NewSessionTokenKeyring() *SessionTokenKeyring {
  pw_prompt := func(utype pb.Aws_UserType) types.PwPromptF {
    prompt_mes := fmt.Sprintf("Input password for AWS user '%s'", utype.String())
    return BuildPwPromt(prompt_mes)
  }
  client_builder := func(cfg aws.Config) StsClientIf {
    return sts.NewFromConfig(cfg)
  }
  return NewSessionTokenKeyringHelper(client_builder, pw_prompt)
}

func NewSessionTokenKeyringHelper(
    client_builder StsClientBuilderF, pw_prompt func(pb.Aws_UserType) types.PwPromptF) *SessionTokenKeyring {
  return &SessionTokenKeyring{
    Mutex: new(sync.Mutex),
    Keyring: make(map[pb.Aws_UserType]aws.Credentials),
    PwPrompt: pw_prompt,
    StsClientBuilder: client_builder,
    Duration: 12*time.Hour,
    RefreshThreshold: 1*time.Hour,
  }
}

func init() {
  globalKeyring = *NewSessionTokenKeyring()
}

func (self *SessionTokenKeyring) ShouldRefresh(token *aws.Credentials) bool {
  if !token.CanExpire { util.Fatalf("Should not store permanent credentials") }
  left := time.Now().Sub(token.Expires).Abs()
  return (left < self.RefreshThreshold)
}

func permAwsCredFromConf(
    pw_prompt types.PwPromptF, cred *pb.Aws_Credential) (aws.Credentials, error) {
  pw, err := pw_prompt()
  if err != nil { return aws.Credentials{}, err }
  perm_cred, err := AesDecryptString(pw, types.PersistableString{cred.Key})
  if err != nil { return aws.Credentials{}, err }

  type JsonPermCred struct {
    Version int
    AccessKeyId string
    SecretAccessKey string
  }
  json_prem_cred := JsonPermCred{}
  err = json.Unmarshal(NoCopyStringToByteSlice(perm_cred.S), &json_prem_cred)

  return aws.Credentials{
    AccessKeyID: json_prem_cred.AccessKeyId,
    SecretAccessKey: json_prem_cred.SecretAccessKey,
  }, err
}

func (self *SessionTokenKeyring) CallAwsStsGetSessionToken(
  ctx context.Context, conf *pb.Config, aws_perm_cred *aws.Credentials) (aws.Credentials, error) {
  cfg, err := config.LoadDefaultConfig(
    ctx,
    config.WithCredentialsProvider(credentials.StaticCredentialsProvider{*aws_perm_cred}),
    config.WithDefaultRegion(conf.Aws.Region),
  )
  if err != nil { return aws.Credentials{}, err }

  client := self.StsClientBuilder(cfg)
  var expire int32 = int32(self.Duration.Seconds())
  rq := &sts.GetSessionTokenInput{ DurationSeconds: &expire, }
  rs, err := client.GetSessionToken(ctx, rq)
  if err != nil { return aws.Credentials{}, err }

  aws_temp_cred := aws.Credentials{
    AccessKeyID: *rs.Credentials.AccessKeyId,
    SecretAccessKey: *rs.Credentials.SecretAccessKey,
    SessionToken: *rs.Credentials.SessionToken,
    Expires: *rs.Credentials.Expiration,
    CanExpire: true,
  }
  return aws_temp_cred, nil
}

func (self *SessionTokenKeyring) GetSessionTokenFor(
    ctx context.Context, conf *pb.Config, cred *pb.Aws_Credential) (aws.Credentials, error) {
  self.Mutex.Lock()
  defer self.Mutex.Unlock()
  if token, found := self.Keyring[cred.Type]; found {
    if !self.ShouldRefresh(&token) { return token, nil }
  }
  aws_perm_cred, err := permAwsCredFromConf(self.PwPrompt(cred.Type), cred)
  if err != nil { return aws.Credentials{}, err }
  aws_temp_cred, err := self.CallAwsStsGetSessionToken(ctx, conf, &aws_perm_cred)
  if err != nil { return aws.Credentials{}, err }
  self.Keyring[cred.Type] = aws_temp_cred
  return aws_temp_cred, nil
}

func NewAwsConfigFromTempCreds(
    ctx context.Context, conf *pb.Config, utype pb.Aws_UserType) (*aws.Config, error) {
  cred, err := util.AwsCredPerUserType(conf, utype)
  if err != nil { return nil, err }
  token, err := globalKeyring.GetSessionTokenFor(ctx, conf, cred)
  if err != nil { return nil, err }
  cfg, err := config.LoadDefaultConfig(
    ctx,
    config.WithCredentialsProvider(credentials.StaticCredentialsProvider{token}),
    config.WithDefaultRegion(conf.Aws.Region),
  )
  return &cfg, err
}

func TestOnlyAwsConfFromPlainKey(
    conf *pb.Config, access_key string, secret_key string, session string) (*aws.Config, error) {
  creds := credentials.StaticCredentialsProvider{
    Value: aws.Credentials{
      AccessKeyID: access_key,
      SecretAccessKey: secret_key,
      SessionToken: session,
    },
  }
  cfg, err := config.LoadDefaultConfig(
    context.Background(),
    config.WithCredentialsProvider(creds),
    config.WithDefaultRegion(conf.Aws.Region),
  )
  return &cfg, err
}

// Pre-requisite:
// File `$HOME/.aws/config` should exist and contain `profile`. Example:
// [profile some_dude]
// region = eu-central-1
// output = json
// credential_process = bash -c 'gpg --quiet --decrypt ~/.aws/some_dude.gpg'
func TestOnlyAwsConfFromCredsFile(
    ctx context.Context, conf *pb.Config, profile string) (*aws.Config, error) {
  cfg, err :=  config.LoadDefaultConfig(ctx,
                                        config.WithDefaultRegion(conf.Aws.Region),
                                        config.WithSharedConfigProfile(profile))
  return &cfg, err
}

