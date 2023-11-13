package encryption

import (
  "context"
  "encoding/json"
  "fmt"
  fpmod "path/filepath"
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
type StsClientBuilderF = func(types.AwsConf) StsClientIf

type JsonPermCred struct {
  Version int
  AccessKeyId string
  SecretAccessKey string
}

type SessionTokenKeyring struct {
  Mutex   *sync.Mutex
  Keyring map[pb.Aws_UserType]aws.Credentials
  PwPrompt         func(pb.Aws_UserType) types.PwPromptF
  InputPrompt      func(string) (types.SecretString, error)
  StsClientBuilder StsClientBuilderF
  Duration         time.Duration
  RefreshThreshold time.Duration
}
var globalKeyring SessionTokenKeyring

func NewSessionTokenKeyring() *SessionTokenKeyring {
  pw_prompt := func(utype pb.Aws_UserType) types.PwPromptF {
    prompt_mes := fmt.Sprintf("Input password for AWS user '%s': ", utype.String())
    if utype == pb.Aws_BACKUP_EXPERIMENTAL { return TestOnlyFixedPw }
    return BuildPwPromt(prompt_mes)
  }
  client_builder := func(cfg types.AwsConf) StsClientIf {
    return sts.NewFromConfig(*cfg.C)
  }
  return NewSessionTokenKeyringHelper(client_builder, pw_prompt, GetSecretMaterialVerbatim)
}

func NewSessionTokenKeyringHelper(
    client_builder StsClientBuilderF, pw_prompt func(pb.Aws_UserType) types.PwPromptF,
    input_prompt func(string) (types.SecretString, error)) *SessionTokenKeyring {
  return &SessionTokenKeyring{
    Mutex: new(sync.Mutex),
    Keyring: make(map[pb.Aws_UserType]aws.Credentials),
    PwPrompt: pw_prompt,
    InputPrompt: input_prompt,
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

  json_prem_cred := JsonPermCred{}
  err = json.Unmarshal(NoCopyStringToByteSlice(perm_cred.S), &json_prem_cred)

  return aws.Credentials{
    AccessKeyID: json_prem_cred.AccessKeyId,
    SecretAccessKey: json_prem_cred.SecretAccessKey,
  }, err
}

func (self *SessionTokenKeyring) CallAwsStsGetSessionToken(
  ctx context.Context, conf *pb.Config, cred *pb.Aws_Credential) (aws.Credentials, error) {
  aws_perm_cred, err := permAwsCredFromConf(self.PwPrompt(cred.Type), cred)
  if err != nil { return aws.Credentials{}, err }
  cfg, err := config.LoadDefaultConfig(
    ctx,
    config.WithCredentialsProvider(credentials.StaticCredentialsProvider{aws_perm_cred}),
    config.WithDefaultRegion(conf.Aws.Region),
  )
  if err != nil { return aws.Credentials{}, err }

  client := self.StsClientBuilder(types.AwsConf{&cfg, cred.Key})
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
  aws_temp_cred, err := self.CallAwsStsGetSessionToken(ctx, conf, cred)
  if err != nil { return aws.Credentials{}, err }
  self.Keyring[cred.Type] = aws_temp_cred
  return aws_temp_cred, nil
}

func (self *SessionTokenKeyring) EncryptAwsCreds(utype pb.Aws_UserType) (*pb.Aws_Credential, error) {
  access_key, err := self.InputPrompt("Enter IAM user AccessKeyId: ")
  if err != nil { return nil, err }
  secret_key, err := self.InputPrompt("Enter IAM user SecretAccessKey: ")
  if err != nil { return nil, err }

  json_creds := JsonPermCred{
    Version:1,
    AccessKeyId: access_key.S,
    SecretAccessKey: secret_key.S,
  }
  byte_creds, err := json.Marshal(&json_creds)
  if err != nil { return nil, err }

  pw, err := self.PwPrompt(utype)()
  if err != nil { return nil, err }
  encrypt_creds := &pb.Aws_Credential{
    Type: utype,
    Key: AesEncryptString(pw, types.SecretString{string(byte_creds)}).S,
  }
  return encrypt_creds, nil
}

func NewAwsConfigFromTempCreds(
    ctx context.Context, conf *pb.Config, utype pb.Aws_UserType) (types.AwsConf, error) {
  cred, err := util.AwsCredPerUserType(conf, utype)
  if err != nil { return types.AwsConf{}, err }
  token, err := globalKeyring.GetSessionTokenFor(ctx, conf, cred)
  if err != nil { return types.AwsConf{}, err }
  cfg, err := config.LoadDefaultConfig(
    ctx,
    config.WithCredentialsProvider(credentials.StaticCredentialsProvider{token}),
    config.WithDefaultRegion(conf.Aws.Region),
  )
  return types.AwsConf{&cfg, cred.Key}, err
}

// You need to first go the IAM console, revoke the old key and create a new one.
func EncryptAwsCreds(utype pb.Aws_UserType) (*pb.Aws_Credential, error) {
  return globalKeyring.EncryptAwsCreds(utype)
}

func TestOnlyAwsConfFromPlainKey(
    conf *pb.Config, access_key string, secret_key string, session string) (types.AwsConf, error) {
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
  return types.AwsConf{&cfg, secret_key}, err
}

// Pre-requisite:
// File `homedir/.aws/config` should exist and contain `profile`. Example:
// [profile some_dude]
// region = eu-central-1
// output = json
// credential_process = bash -c 'gpg --quiet --decrypt ~/.aws/some_dude.gpg'
func TestOnlyAwsConfFromCredsFile(
    ctx context.Context, conf *pb.Config, homedir string, profile string) (types.AwsConf, error) {
  path := fpmod.Join(homedir, ".aws/config")
  cfg, err :=  config.LoadDefaultConfig(ctx,
                                        config.WithDefaultRegion(conf.Aws.Region),
                                        config.WithSharedConfigProfile(profile),
                                        config.WithSharedConfigFiles([]string{path}))
  return types.AwsConf{&cfg, profile}, err
}

