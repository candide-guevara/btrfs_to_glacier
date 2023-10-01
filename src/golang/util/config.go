package util

import (
  "errors"
  "fmt"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
)

var ErrNotFoundByName = errors.New("not_found_by_name")
var ErrNotFoundByType = errors.New("not_found_by_type")

func Load() (*pb.Config, error) {
  conf := &pb.Config{}
  // TODO Merge default values
  err := Validate(conf)
  return conf, err
}

func SourceByName(conf *pb.Config, name string) (*pb.Source, error) {
  for _,s := range conf.Sources {
    if s.Name == name { return s, nil }
  }
  return nil, fmt.Errorf("source %w %s", ErrNotFoundByName, name)
}

func RestoreByName(conf *pb.Config, name string) (*pb.Restore, error) {
  for _,r := range conf.Restores {
    if r.Name == name { return r, nil }
  }
  return nil, fmt.Errorf("restore %w %s", ErrNotFoundByName, name)
}

func BackupByName(conf *pb.Config, name string) (*pb.Backup, error) {
  for _,b := range conf.Backups {
    if b.Name == name { return b, nil }
  }
  return nil, fmt.Errorf("backup %w %s", ErrNotFoundByName, name)
}

func BackupAwsByName(conf *pb.Config, name string) (*pb.Backup_Aws, error) {
  for _,b := range conf.Backups {
    if b.Name == name && b.Aws != nil { return b.Aws, nil }
  }
  return nil, fmt.Errorf("backup.aws %w %s", ErrNotFoundByName, name)
}

func BackupPartitionByUuid(conf *pb.Config, name string) (*pb.Backup_Partition, error) {
  for _,b := range conf.Backups {
    if b.Fs == nil { continue }
    for _,p := range b.Fs.Sinks {
      if p.FsUuid == name { return p, nil }
    }
  }
  return nil, fmt.Errorf("backup.partition %w %s", ErrNotFoundByName, name)
}

func AwsCredPerUserType(conf *pb.Config, utype pb.Aws_UserType) (*pb.Aws_Credential, error) {
  for _,b := range conf.Aws.Creds {
    if b.Type == utype { return b, nil }
  }
  return nil, fmt.Errorf("%w %s", ErrNotFoundByType, utype.String())
}

func WorkflowByName(conf *pb.Config, name string) (types.ParsedWorkflow, error) {
  parsed := types.ParsedWorkflow{}
  for _,w := range conf.Workflows {
    if w.Name == name { parsed.Wf = w ; continue }
  }
  if parsed.Wf == nil { return parsed, fmt.Errorf("workflow %w %s", ErrNotFoundByName, name) }

  for _,s := range conf.Sources {
    if s.Name == parsed.Wf.Source { parsed.Source = s ; continue }
  }
  if parsed.Source == nil { return parsed, fmt.Errorf("workflow.source %w %s", ErrNotFoundByName, parsed.Wf.Source) }

  for _,b := range conf.Backups {
    if b.Name == parsed.Wf.Backup { parsed.Backup = b ; continue }
  }
  if parsed.Backup == nil { return parsed, fmt.Errorf("workflow.backup %w %s", ErrNotFoundByName, parsed.Wf.Backup) }

  for _,r := range conf.Restores {
    if r.Name == parsed.Wf.Restore { parsed.Restore = r ; continue }
  }
  if parsed.Restore == nil { return parsed, fmt.Errorf("workflow.restore %w %s", ErrNotFoundByName, parsed.Wf.Restore) }

  return parsed, nil
}

func Validate(conf *pb.Config) error {
  // Each subvolume should be mentioned in only 1 source
  // Sources, Stores, Restores, Workflows, Tools have a unique name
  // Reference by name not dangling
  return nil
}

