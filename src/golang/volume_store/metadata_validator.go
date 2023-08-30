package volume_store

import (
  "errors"
  "fmt"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/util"
)

type CheckType int
const (
  CheckSvInSeq CheckType = iota
  CheckSnapNoContent CheckType = iota
  CheckSnapWithContent CheckType = iota
  CheckChunkNotFirst CheckType = iota
  CheckChunkFromStart CheckType = iota
)

func ValidateSnapshotChunks(check CheckType, chunks *pb.SnapshotChunks) error {
  if chunks == nil { return errors.New("SnapshotChunks == nil") }
  if len(chunks.Chunks) < 1 { return util.PbErrorf("No chunks: %v", chunks) }
  if chunks.KeyFingerprint == "" { return util.PbErrorf("Chunks no key fingerprint: %v", chunks) }

  var last_offset uint64 = 0
  uuids := make(map[string]bool)
  for _, chunk := range chunks.Chunks {
    if _,found := uuids[chunk.Uuid]; found { return util.PbErrorf("Chunk duplicate uuid: %v", chunk) }
    uuids[chunk.Uuid] = true
    if chunk.Uuid == "" { return util.PbErrorf("No chunk uuid: %v", chunk) }
    if chunk.Size == 0 { return util.PbErrorf("No chunk size: %v", chunk) }
    switch check {
      case CheckChunkFromStart:
        if last_offset != chunk.Start { return util.PbErrorf("Bad chunk order: %v", chunk) }
      default:
    }
    last_offset = chunk.Start + chunk.Size
  }
  return nil
}

func ValidateSystemInfo(si *pb.SystemInfo) error {
  if si == nil { return errors.New("SystemInfo == nil") }
  if si.KernMajor == 0 { return util.PbErrorf("SystemInfo no kernel version: %v", si) }
  if si.BtrfsUsrMajor == 0 { return util.PbErrorf("SystemInfo no btrfs user lib version: %v", si) }
  if si.ToolGitCommit == "" { return util.PbErrorf("SystemInfo no git hash: %v", si) }
  return nil
}

func SubVolumeDataLen(sv *pb.SubVolume) uint64 {
  if sv == nil { panic("SubVolume == nil") }
  var data_len uint64= 0
  if sv.Data != nil {
    for _, chunk := range sv.Data.Chunks { data_len += chunk.Size }
  }
  return data_len
}

func ValidateSubVolume(check CheckType, sv *pb.SubVolume) error {
  if sv == nil { return errors.New("SubVolume == nil") }
  if sv.Uuid == "" { return util.PbErrorf("Volume no uuid: %v", sv) }
  switch check {
    case CheckSvInSeq:
      if sv.CreatedTs == 0 { return util.PbErrorf("Volume no creation timestamp: %v", sv) }
      return ValidateSystemInfo(sv.OriginSys)
    case CheckSnapNoContent:
      if sv.ParentUuid == "" { return util.PbErrorf("Snapshot no parent: %v", sv) }
      if sv.GenAtCreation == 0 { return util.PbErrorf("Snapshot no creation generation: %v", sv) }
      if sv.CreatedTs == 0 { return util.PbErrorf("Snapshot no creation timestamp: %v", sv) }
      if sv.ReadOnly == false { return util.PbErrorf("Snapshot cannot be writable: %v", sv) }
      return ValidateSystemInfo(sv.OriginSys)
    case CheckSnapWithContent:
      if sv.ParentUuid == "" { return util.PbErrorf("Snapshot no parent: %v", sv) }
      if sv.GenAtCreation == 0 { return util.PbErrorf("Snapshot no creation generation: %v", sv) }
      if sv.CreatedTs == 0 { return util.PbErrorf("Snapshot no creation timestamp: %v", sv) }
      if sv.ReadOnly == false { return util.PbErrorf("Snapshot cannot be writable: %v", sv) }
      err := ValidateSnapshotChunks(CheckChunkFromStart, sv.Data)
      if err != nil { return err }
      return ValidateSystemInfo(sv.OriginSys)
    default:
      return nil
  }
}

// * Volume backed up is correctly formed.
// * No duplicate or invalid snapshot uuids.
func ValidateSnapshotSequence(seq *pb.SnapshotSequence) error {
  if seq == nil { return errors.New("SnapshotSequence == nil") }
  if seq.Uuid == "" { return util.PbErrorf("Bad sequence uuid: %v", seq) }
  err := ValidateSubVolume(CheckSvInSeq, seq.Volume)
  if err != nil { return err }
  if len(seq.SnapUuids) < 1 { return util.PbErrorf("Sequence has no snapshots: %v", seq) }

  uuids := make(map[string]bool)
  for _, uuid := range seq.SnapUuids {
    if _,found := uuids[uuid]; found { return fmt.Errorf("Snapshot duplicate uuid: %v", uuid) }
    uuids[uuid] = true
    if uuid == "" { return util.PbErrorf("Sequence has empty uuid: %v", seq) }
  }
  return nil
}

// * No duplicate previous sequences.
// * Current sequence is not also a previous one.
func ValidateSnapshotSeqHead(head *pb.SnapshotSeqHead) error {
  if head == nil { return errors.New("SnapshotSeqHead == nil") }
  if head.Uuid == "" { return util.PbErrorf("Bad volume uuid: %v", head) }
  if head.CurSeqUuid == "" { return util.PbErrorf("No current sequence: %v", head) }

  uuids := make(map[string]bool)
  for _, uuid := range head.PrevSeqUuid {
    if _,found := uuids[uuid]; found { return fmt.Errorf("Sequence duplicate uuid: %v", uuid) }
    uuids[uuid] = true
    if uuid == "" { return fmt.Errorf("Sequence has empty uuid") }
    if uuid == head.CurSeqUuid { return util.PbErrorf("Head has current and previous for same uuid: %v", head) }
  }
  return nil
}

func IsFullyContainedInSubvolume(snap *pb.SubVolume, data *pb.SnapshotChunks) bool {
  if snap.Data == nil { return false }

  for start_idx,chunk_snap := range snap.Data.Chunks {
    if chunk_snap.Start == data.Chunks[0].Start {
      for idx,chunk_chunk := range data.Chunks {
        snap_idx := idx + start_idx
        if snap_idx >= len(snap.Data.Chunks) { return false }
        if snap.Data.Chunks[snap_idx].Start != chunk_chunk.Start { return false }
        if snap.Data.Chunks[snap_idx].Size != chunk_chunk.Size { return false }
      }
      return true
    }
  }
  return false
}

