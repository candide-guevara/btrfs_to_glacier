package garbage_collector

import (
  "context"
  "sort"
  "time"
  "testing"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

func TestDummyDataProperties(t *testing.T) {
  meta, store := mocks.DummyMetaAndStorage(1,2,3,4)
  util.EqualsOrFailTest(t, "Bad chunk count", len(store.Chunks), 24)
  util.EqualsOrFailTest(t, "Bad snap count", len(meta.Snaps), 6)
  for _,snap := range meta.Snaps {
    for _,chunk := range snap.Data.Chunks {
      _,found := store.Chunks[chunk.Uuid]
      util.EqualsOrFailTest(t, "Chunk not found in storage", found, true)
    }
  }
  meta, store = mocks.DummyMetaAndStorage(4,3,2,1)
  util.EqualsOrFailTest(t, "Bad chunk count", len(store.Chunks), 24)
  util.EqualsOrFailTest(t, "Bad snap count", len(meta.Snaps), 24)
  for _,snap := range meta.Snaps {
    for _,chunk := range snap.Data.Chunks {
      _,found := store.Chunks[chunk.Uuid]
      util.EqualsOrFailTest(t, "Chunk not found in storage", found, true)
    }
  }
  meta, store = mocks.DummyMetaAndStorage(1,1,1,1)
  util.EqualsOrFailTest(t, "Bad chunk count", len(store.Chunks), 1)
  util.EqualsOrFailTest(t, "Bad snap count", len(meta.Snaps), 1)
}

func buildTestGarbageCollector(t *testing.T, branch_factor int) (*mocks.Metadata, *mocks.Storage, *garbageCollector) {
  conf := util.LoadTestConf()
  meta, store := mocks.DummyMetaAndStorage(branch_factor, branch_factor, branch_factor, branch_factor)
  gc, err := NewGarbageCollector(conf, meta, store)
  if err != nil { t.Fatalf("Failed to construct gc: %v", err) }
  return meta, store, gc.(*garbageCollector)
}

func compareResult(t *testing.T, got types.DeletedObjectsOrErr, expect types.DeletedObjectsOrErr) {
  var expect_uuids []string
  var got_uuids []string
  for _,chunk := range got.Chunks { got_uuids = append(got_uuids, chunk.Uuid) }
  for _,chunk := range expect.Chunks { expect_uuids = append(expect_uuids, chunk.Uuid) }
  sort.Strings(got_uuids)
  sort.Strings(expect_uuids)
  util.EqualsOrFailTest(t, "Bad chunk uuids", got_uuids, expect_uuids)

  expect_uuids = nil
  got_uuids = nil
  for _,snap := range    got.Snaps { got_uuids    = append(got_uuids,    snap.Uuid) }
  for _,snap := range expect.Snaps { expect_uuids = append(expect_uuids, snap.Uuid) }
  sort.Strings(expect_uuids)
  sort.Strings(got_uuids)
  util.EqualsOrFailTest(t, "Bad snap uuids", got_uuids, expect_uuids)

  expect_uuids = nil
  got_uuids = nil
  for _,seq := range    got.Seqs { got_uuids    = append(got_uuids,    seq.Uuid) }
  for _,seq := range expect.Seqs { expect_uuids = append(expect_uuids, seq.Uuid) }
  sort.Strings(expect_uuids)
  sort.Strings(got_uuids)
  util.EqualsOrFailTest(t, "Bad sequence uuids", got_uuids, expect_uuids)
}

func TestCleanUnreachableChunks_NoneFound(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  _, store, gc := buildTestGarbageCollector(t, 3)
  expect_store := len(store.Chunks)
  expect_result := types.DeletedObjectsOrErr{}
  var got_result types.DeletedObjectsOrErr

  done := gc.CleanUnreachableChunks(ctx, false)
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_store := len(store.Chunks)
  util.EqualsOrFailTest(t, "Deleted some chunk", got_store, expect_store)
  util.EqualsOrFailTest(t, "Bad result", got_result, expect_result)
}

func TestCleanUnreachableChunks_FromSingleSnap(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, store, gc := buildTestGarbageCollector(t, 3)
  snap := meta.Snaps[meta.SnapKeys()[0]]
  expect_store := len(store.Chunks) - len(snap.Data.Chunks)
  expect_result := types.DeletedObjectsOrErr{
    Chunks: snap.Data.Chunks,
  }
  snap.Data.Chunks = nil
  var got_result types.DeletedObjectsOrErr

  done := gc.CleanUnreachableChunks(ctx, false)
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_store := len(store.Chunks)
  util.EqualsOrFailTest(t, "Bad delete count", got_store, expect_store)
  compareResult(t, got_result, expect_result)
}

func TestCleanUnreachableChunks_DryRun(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, store, gc := buildTestGarbageCollector(t, 3)
  snap := meta.Snaps[meta.SnapKeys()[0]]
  expect_store := len(store.Chunks)
  snap.Data.Chunks = nil

  done := gc.CleanUnreachableChunks(ctx, true)
  select {
    case <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_store := len(store.Chunks)
  util.EqualsOrFailTest(t, "Bad delete count", got_store, expect_store)
}

func TestCleanUnreachableChunks_FromManySnaps(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, store, gc := buildTestGarbageCollector(t, 3)
  expect_result := types.DeletedObjectsOrErr{ }
  expect_store := len(store.Chunks) - len(meta.SnapKeys())
  for _,uuid := range meta.SnapKeys() {
    snap := meta.Snaps[uuid]
    expect_result.Chunks = append(expect_result.Chunks, snap.Data.Chunks[0])
    snap.Data.Chunks = snap.Data.Chunks[1:]
  }
  var got_result types.DeletedObjectsOrErr

  done := gc.CleanUnreachableChunks(ctx, false)
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_store := len(store.Chunks)
  util.EqualsOrFailTest(t, "Bad delete count", got_store, expect_store)
  compareResult(t, got_result, expect_result)
}

func TestCleanUnreachableMetadata_NothingToClean(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, _, gc := buildTestGarbageCollector(t, 3)
  expect_cnt := meta.ObjCounts()
  expect_result := types.DeletedObjectsOrErr{}
  var got_result types.DeletedObjectsOrErr

  done := gc.CleanUnreachableMetadata(ctx, false)
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_cnt := meta.ObjCounts()
  util.EqualsOrFailTest(t, "Bad count", got_cnt, expect_cnt)
  util.EqualsOrFailTest(t, "Bad result", got_result, expect_result)
}

func TestCleanUnreachableMetadata_CleanSnaps(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, _, gc := buildTestGarbageCollector(t, 3)
  expect_cnt := meta.ObjCounts()
  expect_cnt[2] -= len(meta.Seqs)
  expect_result := types.DeletedObjectsOrErr{}
  for _,seq := range meta.Seqs {
    expect_result.Snaps = append(expect_result.Snaps, &pb.SubVolume{ Uuid:seq.SnapUuids[0], })
    seq.SnapUuids = seq.SnapUuids[1:]
  }
  var got_result types.DeletedObjectsOrErr

  done := gc.CleanUnreachableMetadata(ctx, false)
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_cnt := meta.ObjCounts()
  util.EqualsOrFailTest(t, "Bad count", got_cnt, expect_cnt)
  compareResult(t, got_result, expect_result)
}

func TestCleanUnreachableMetadata_DryRun(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, _, gc := buildTestGarbageCollector(t, 3)
  delete(meta.Seqs, meta.SeqKeys()[0])
  expect_cnt := meta.ObjCounts()

  done := gc.CleanUnreachableMetadata(ctx, true)
  select {
    case <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_cnt := meta.ObjCounts()
  util.EqualsOrFailTest(t, "Bad count", got_cnt, expect_cnt)
}

func TestCleanUnreachableMetadata_CleanSeqs(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, _, gc := buildTestGarbageCollector(t, 3)
  expect_cnt := meta.ObjCounts()
  expect_cnt[1] -= len(meta.Heads)
  expect_cnt[2] = (len(meta.Heads)-1) * 3 * 3
  expect_result := types.DeletedObjectsOrErr{}
  for _,head := range meta.Heads {
    expect_result.Seqs = append(expect_result.Seqs, &pb.SnapshotSequence{ Uuid:head.PrevSeqUuid[0], })
    for _,uuid := range meta.Seqs[head.PrevSeqUuid[0]].SnapUuids {
      expect_result.Snaps = append(expect_result.Snaps, &pb.SubVolume{ Uuid:uuid, })
    }
    head.PrevSeqUuid = head.PrevSeqUuid[1:]
  }
  var got_result types.DeletedObjectsOrErr

  done := gc.CleanUnreachableMetadata(ctx, false)
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_cnt := meta.ObjCounts()
  util.EqualsOrFailTest(t, "Bad count", got_cnt, expect_cnt)
  compareResult(t, got_result, expect_result)
}

func TestCleanUnreachableMetadata_CleanAllHeadChildren(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, _, gc := buildTestGarbageCollector(t, 3)
  expect_cnt := meta.ObjCounts()
  expect_cnt[0] -= 1
  expect_cnt[2] -= len(meta.Seqs)
  expect_cnt[1] -= len(meta.Heads)
  delete(meta.Heads, meta.HeadKeys()[0])

  done := gc.CleanUnreachableMetadata(ctx, false)
  select {
    case <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_cnt := meta.ObjCounts()
  util.EqualsOrFailTest(t, "Bad count", got_cnt, expect_cnt)
}

func TestDeleteSnapshotSeqHead_NotInMeta(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, store, gc := buildTestGarbageCollector(t, 3)
  expect_meta_cnt := meta.ObjCounts()
  expect_store_cnt := len(store.Chunks)
  expect_result := types.DeletedObjectsOrErr{}
  expect_heads := meta.CloneHeads()

  var got_result types.DeletedObjectsOrErr
  done := gc.DeleteSnapshotSequence(ctx, false, "not_a_seq_uuid")
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_meta_cnt := meta.ObjCounts()
  got_store_cnt := len(store.Chunks)
  util.EqualsOrFailTest(t, "Bad meta count", got_meta_cnt, expect_meta_cnt)
  util.EqualsOrFailTest(t, "Bad store count", got_store_cnt, expect_store_cnt)
  util.EqualsOrFailTest(t, "Bad result", got_result, expect_result)
  util.EqualsOrFailTest(t, "Bad heads", meta.Heads, expect_heads)
}

func TestDeleteSnapshotSeqHead_CurrentHead(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, store, gc := buildTestGarbageCollector(t, 3)
  expect_meta_cnt := meta.ObjCounts()
  expect_store_cnt := len(store.Chunks)
  seq_uuid := meta.Heads[meta.HeadKeys()[1]].CurSeqUuid

  var got_result types.DeletedObjectsOrErr
  done := gc.DeleteSnapshotSequence(ctx, false, seq_uuid)
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_meta_cnt := meta.ObjCounts()
  got_store_cnt := len(store.Chunks)
  util.EqualsOrFailTest(t, "Bad meta count", got_meta_cnt, expect_meta_cnt)
  util.EqualsOrFailTest(t, "Bad store count", got_store_cnt, expect_store_cnt)
  if got_result.Err == nil { t.Errorf("Expected error in return value.") }
}

func TestDeleteSnapshotSeqHead_Simple(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, store, gc := buildTestGarbageCollector(t, 3)
  expect_meta_cnt := meta.ObjCounts()
  expect_meta_cnt[1] -= 1
  expect_meta_cnt[2] -= 3
  expect_store_cnt := len(store.Chunks) - 9

  head_uuid := meta.HeadKeys()[1]
  expect_heads := meta.CloneHeads()
  new_seq_uuids := expect_heads[head_uuid].PrevSeqUuid
  expect_heads[head_uuid].PrevSeqUuid = append(new_seq_uuids[:1], new_seq_uuids[2:]...)
  seq_uuid := meta.Heads[head_uuid].PrevSeqUuid[1]

  expect_result := types.DeletedObjectsOrErr{
    Seqs: []*pb.SnapshotSequence{ &pb.SnapshotSequence{ Uuid:seq_uuid, }, },
  }
  for _,snap_uuid := range meta.Seqs[seq_uuid].SnapUuids {
    expect_result.Snaps = append(expect_result.Snaps, &pb.SubVolume{ Uuid:snap_uuid, })
    for _,chunk := range meta.Snaps[snap_uuid].Data.Chunks {
      expect_result.Chunks = append(expect_result.Chunks, &pb.SnapshotChunks_Chunk{ Uuid:chunk.Uuid, })
    }
  }

  var got_result types.DeletedObjectsOrErr
  done := gc.DeleteSnapshotSequence(ctx, false, seq_uuid)
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_meta_cnt := meta.ObjCounts()
  got_store_cnt := len(store.Chunks)
  util.EqualsOrFailTest(t, "Bad meta count", got_meta_cnt, expect_meta_cnt)
  util.EqualsOrFailTest(t, "Bad store count", got_store_cnt, expect_store_cnt)
  util.EqualsOrFailTest(t, "Bad heads", meta.Heads, expect_heads)
  compareResult(t, got_result, expect_result)
}

func TestDeleteSnapshotSeqHead_DryRun(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
  defer cancel()
  meta, store, gc := buildTestGarbageCollector(t, 3)
  expect_meta_cnt := meta.ObjCounts()
  expect_store_cnt := len(store.Chunks)

  head_uuid := meta.HeadKeys()[1]
  expect_heads := meta.CloneHeads()
  seq_uuid := meta.Heads[head_uuid].PrevSeqUuid[1]

  expect_result := types.DeletedObjectsOrErr{
    Seqs: []*pb.SnapshotSequence{ &pb.SnapshotSequence{ Uuid:seq_uuid, }, },
  }
  for _,snap_uuid := range meta.Seqs[seq_uuid].SnapUuids {
    expect_result.Snaps = append(expect_result.Snaps, &pb.SubVolume{ Uuid:snap_uuid, })
    for _,chunk := range meta.Snaps[snap_uuid].Data.Chunks {
      expect_result.Chunks = append(expect_result.Chunks, &pb.SnapshotChunks_Chunk{ Uuid:chunk.Uuid, })
    }
  }

  var got_result types.DeletedObjectsOrErr
  done := gc.DeleteSnapshotSequence(ctx, true, seq_uuid)
  select {
    case got_result = <-done:
    case <-ctx.Done(): t.Fatal("timeout")
  }

  got_meta_cnt := meta.ObjCounts()
  got_store_cnt := len(store.Chunks)
  util.EqualsOrFailTest(t, "Bad meta count", got_meta_cnt, expect_meta_cnt)
  util.EqualsOrFailTest(t, "Bad store count", got_store_cnt, expect_store_cnt)
  util.EqualsOrFailTest(t, "Bad heads", meta.Heads, expect_heads)
  compareResult(t, got_result, expect_result)
}

