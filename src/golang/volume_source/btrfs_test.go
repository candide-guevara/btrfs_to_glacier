package volume_source

import (
  "context"
  "errors"
  "fmt"
  fpmod "path/filepath"
  "io/ioutil"
  "math/rand"
  "sort"
  "testing"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"
  "google.golang.org/protobuf/proto"

  "github.com/google/uuid"
)

func CloneSubvol(vol *pb.SubVolume) *pb.SubVolume { return proto.Clone(vol).(*pb.SubVolume) }

func buildTestManager() (*btrfsVolumeManager, *mocks.Btrfsutil, *mocks.BtrfsPathJuggler) {
  newfile_ops := types.SendDumpOperations{
    Written: map[string]bool{
      "coucou": true,
    },
    New: map[string]bool{
      "o260-8-0": true,
    },
    NewDir: map[string]bool{},
    Deleted: map[string]bool{},
    DelDir: map[string]bool{},
    FromTo: map[string]string{
      "o260-8-0": "coucou",
    },
    ToUuid: "72124d274e1e67428b7eed6909b00537",
    FromUuid: "5196e8fc2aa495499e24d9df818ba8c7",
  }
  sys_info := &pb.SystemInfo{
    KernMajor: 1,
    KernMinor: 2,
    BtrfsUsrMajor: 3,
    BtrfsUsrMinor: 4,
    ToolGitCommit: "hash",
  }
  mock_subvol := util.DummySubVolume("uuid")
  mock_subvol.GenAtCreation = 66
  mock_snap1 := util.DummySnapshot("uuid2", "uuid")
  mock_snap1.ReceivedUuid = "uuid4"
  mock_snap1.GenAtCreation = 99
  mock_snap2 := util.DummySnapshot("uuid3", "uuid")
  mock_snap2.GenAtCreation = 77
  mock_snap3 := util.DummySnapshot("uuid4", "uuid0")
  mock_snap3.GenAtCreation = 55
  mock_snap4 := util.DummySubVolume("uuid0")
  mock_snap4.GenAtCreation = 33
  mock_snap5 := util.DummySnapshot("uuid5", "uuid")
  mock_snap5.GenAtCreation = 88

  source := &pb.Source{
    Type: pb.Source_BTRFS,
    Paths: []*pb.Source_VolSnapPathPair{
      &pb.Source_VolSnapPathPair{
        VolPath: mock_subvol.MountedPath,
        SnapPath: "/tmp/snaps",
      },
    },
    History: &pb.Source_SnapHistory{
      DaysKeepAll: 10,
      KeepOnePeriodDays: 10,
    },
  }

  conf := util.LoadTestConf()
  conf.Sources = []*pb.Source{ source }
  btrfsutil := &mocks.Btrfsutil {
    Subvols: []*pb.SubVolume{ CloneSubvol(mock_subvol), },
    Snaps: []*pb.SubVolume{
      CloneSubvol(mock_snap1),
      CloneSubvol(mock_snap2),
      CloneSubvol(mock_snap3),
      CloneSubvol(mock_snap4),
      CloneSubvol(mock_snap5),
    },
    DumpOps: &newfile_ops,
    SendStream: mocks.NewPreloadedPipe([]byte("somedata")),
  }

  mnts := []*types.MountEntry{
    util.DummyMountEntryForSv(mock_subvol),
    util.DummyMountEntry(256, source.Paths[0].SnapPath,
                         fpmod.Dir(mock_snap2.TreePath)),
  }
  fs := util.DummyFilesystem(mnts)
  juggler := &mocks.BtrfsPathJuggler{}
  juggler.LoadFilesystem(fs)
  juggler.LoadSubVolume(fs, mnts[0], mock_subvol)
  juggler.LoadSubVolume(fs, mnts[1], mock_snap2, mock_snap3, mock_snap4, mock_snap5)

  linuxutil := &mocks.Linuxutil{ SysInfo: sys_info, }

  volmgr, err := NewVolumeManager(conf, btrfsutil, linuxutil, juggler)
  if err != nil { util.Fatalf("NewVolumeManager: %v", err) }
  if _, ok := volmgr.(types.VolumeDestination); !ok { util.Fatalf("cannot cast VolumeDestination") }
  if _, ok := volmgr.(types.VolumeSource); !ok { util.Fatalf("cannot cast VolumeSource") }
  if _, ok := volmgr.(types.VolumeAdmin); !ok { util.Fatalf("cannot cast VolumeAdmin") }
  mgr := volmgr.(*btrfsVolumeManager)
  mgr.TestOnlySwapSrcFsList([]*types.Filesystem{ fs, })
  return mgr, btrfsutil, juggler
}

func defaultVolPath(conf *pb.Config) string {
  return conf.Sources[0].Paths[0].VolPath
}

func TestGetVolume(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  expect_subvol := CloneSubvol(btrfsutil.Subvols[0])
  expect_subvol.OriginSys = proto.Clone(volmgr.k_sysinfo).(*pb.SystemInfo)
  subvol, err := volmgr.GetVolume(defaultVolPath(volmgr.conf))
  if err != nil { t.Fatalf("%s", err) }
  if !proto.Equal(expect_subvol, subvol) {
    t.Errorf("\n%s\n !=\n %s", expect_subvol, subvol)
  }
  // Just test we are not reusing internal references
  new_sysinfo := proto.Clone(volmgr.k_sysinfo).(*pb.SystemInfo)
  new_sysinfo.ToolGitCommit = "another_hash"
  volmgr.TestOnlySwapSysInfo(new_sysinfo)
  util.EqualsOrFailTest(t, "Using internal refs", expect_subvol, subvol)
}

func TestListVolumes(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  vols, err := volmgr.ListVolumes(defaultVolPath(volmgr.conf))
  if err != nil { t.Fatalf("%s", err) }
  util.EqualsOrFailTest(t, "Bad vol list", len(vols), btrfsutil.VolCount())
}

func TestFindVolume(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  expect_subvol := CloneSubvol(btrfsutil.Snaps[0])
  subvol, err := volmgr.FindVolume(defaultVolPath(volmgr.conf),
                                   types.ByReceivedUuid(expect_subvol.ReceivedUuid))
  if err != nil { t.Fatalf("%s", err) }
  if !proto.Equal(expect_subvol, subvol) {
    t.Errorf("\n%s\n !=\n %s", expect_subvol, subvol)
  }

  subvol, err = volmgr.FindVolume(defaultVolPath(volmgr.conf),
                                  types.ByReceivedUuid("should not exist as a uuid"))
  if err != nil { t.Fatalf("%s", err) }
  if subvol != nil { t.Errorf("Expected to find no subvolume, got %s", subvol) }
}

func TestGetSnapshotSeqForVolume(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  expect_snaps := []*pb.SubVolume {
    CloneSubvol(btrfsutil.Snaps[1]),
    CloneSubvol(btrfsutil.Snaps[4]),
    CloneSubvol(btrfsutil.Snaps[0]),
  }
  snapseq, err := volmgr.GetSnapshotSeqForVolume(btrfsutil.Subvols[0])
  if err != nil { t.Fatalf("%s", err) }
  if len(snapseq) != len(expect_snaps) {
    t.Fatalf("expected len %d got %d", len(expect_snaps), len(snapseq))
  }
  for idx, expect_snap := range expect_snaps {
    if !proto.Equal(expect_snap, snapseq[idx]) {
      t.Errorf("\n%s\n !=\n %s", expect_snap, snapseq[idx])
    }
  }
}

func TestGetChangesBetweenSnaps(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  expect_changes := &pb.SnapshotChanges{
    FromUuid: btrfsutil.DumpOps.FromUuid,
    ToUuid: btrfsutil.DumpOps.ToUuid,
    Changes: []*pb.SnapshotChanges_Change{
      &pb.SnapshotChanges_Change{
        Type: pb.SnapshotChanges_NEW,
        Path: "coucou",
      },
    },
  }
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
	defer cancel()
  changes, err := volmgr.GetChangesBetweenSnaps(ctx, btrfsutil.Snaps[1], btrfsutil.Snaps[4])
  if err != nil { t.Errorf("GetChangesBetweenSnaps: %v", err) }
  util.EqualsOrFailTest(t, "Bad changes", changes, expect_changes)
}

func TestGetChangesBetweenSnaps_ErrPropagation(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  btrfsutil.SendStream = mocks.NewErrorPipe()
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  _, err := volmgr.GetChangesBetweenSnaps(ctx, btrfsutil.Snaps[1], btrfsutil.Snaps[4])
  if !errors.Is(err, mocks.ErrIoPipe) {
    t.Fatalf("GetChangesBetweenSnaps bad error propagation: %v", err)
  }
}

func TestGetSnapshotStream(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  expect_stream := []byte("somedata")
  btrfsutil.SendStream = mocks.NewPreloadedPipe(expect_stream)

  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  read_pipe, err := volmgr.GetSnapshotStream(ctx, btrfsutil.Snaps[1], btrfsutil.Snaps[4])
  if err != nil { t.Fatalf("GetSnapshotStream: %v", err) }

  done := make(chan []byte)
  go func() {
    defer close(done)
    defer read_pipe.Close()
    data, err := ioutil.ReadAll(read_pipe)
    if err != nil { t.Errorf("GetSnapshotStream bad stream data: %v", err) }
    done <- data
  }()

  select {
    case data := <-done:
      util.EqualsOrFailTest(t, "Bad snap data", data, expect_stream)
    case <-ctx.Done(): t.Fatalf("timedout")
  }
}

func TestGetChangesBetweenSnaps_ErrStartingStream(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  btrfsutil.Err = fmt.Errorf("problemo")
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  changes, err := volmgr.GetChangesBetweenSnaps(ctx, btrfsutil.Snaps[0], btrfsutil.Snaps[1])
  if err == nil { t.Errorf("GetChangesBetweenSnaps expected error") }
  if changes != nil { t.Errorf("Expected nil changes on error") }
}

func TestGetChangesBetweenSnaps_ErrParsingStream(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  btrfsutil.DumpErr = fmt.Errorf("problemo")
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  _, err := volmgr.GetChangesBetweenSnaps(ctx, btrfsutil.Snaps[1], btrfsutil.Snaps[4])
  if err == nil { t.Errorf("GetChangesBetweenSnaps expected error") }
}

func TestCreateSnapshot(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  expect_cnt := len(btrfsutil.Snaps) + 1
  sv := CloneSubvol(btrfsutil.Subvols[0])

  snapshot, err := volmgr.CreateSnapshot(sv)
  if err != nil { t.Fatalf("%s", err) }
  util.EqualsOrFailTest(t, "CreateSnapshot not called", len(btrfsutil.Snaps), expect_cnt)

  if len(snapshot.MountedPath) < 1 { t.Errorf("created snapshot should return mounted path.") }
  for _,snap := range btrfsutil.Snaps {
    var expect pb.SubVolume = *snap
    if snapshot.Uuid == expect.Uuid {
      expect.OriginSys = volmgr.k_sysinfo
      util.EqualsOrFailTest(t, "Bad snapshot", snapshot, &expect)
      return
    }
  }
  t.Errorf("Snapshot was not created")
}

func TestDeleteSnapshot(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  err := volmgr.DeleteSnapshot(btrfsutil.Subvols[0])
  if err == nil { t.Errorf("Expected error when deleting non-readonly subvolumes") }
  //util.Debugf("err: %v", err)
  btrfsutil.Snaps[0].MountedPath = fmt.Sprintf("/snaps/%s", btrfsutil.Snaps[0].TreePath)
  err = volmgr.DeleteSnapshot(btrfsutil.Snaps[0])
  if err != nil { t.Errorf("%s", err) }
  err = volmgr.DeleteSnapshot(btrfsutil.Snaps[0])
  if err == nil { t.Errorf("idempotency should not work for DeleteSnapshot") }
}

func TestReceiveSendStream(t *testing.T) {
  volmgr, btrfsutil, juggler := buildTestManager()
  read_pipe := mocks.NewPreloadedPipe([]byte("somedata")).ReadEnd()
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  recv_path := juggler.UuidToMnt[btrfsutil.Snaps[1].Uuid].MountedPath
  mock_received := util.DummySnapshot(uuid.NewString(), "")
  mock_received.ReceivedUuid = btrfsutil.Snaps[1].Uuid
  mock_received.MountedPath = fpmod.Join(recv_path, mock_received.Uuid)
  btrfsutil.Snaps = append(btrfsutil.Snaps, mock_received)

  sv, err := volmgr.ReceiveSendStream(ctx, recv_path, btrfsutil.Snaps[1], read_pipe)
  if err != nil { t.Errorf("ReceiveSendStream: %v", err) }
  util.EqualsOrFailTest(t, "Bad received subvol", sv, mock_received)
}

func TestReceiveSendStream_ErrNothingCreated(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  read_pipe := mocks.NewPreloadedPipe([]byte("somedata")).ReadEnd()
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  _, err := volmgr.ReceiveSendStream(ctx, "/tmp", btrfsutil.Snaps[1], read_pipe)
  if err == nil { t.Errorf("ReceiveSendStream expected error") }
}

func TestReceiveSendStream_ErrPropagation(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  read_pipe := mocks.NewErrorPipe().ReadEnd()
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  _, err := volmgr.ReceiveSendStream(ctx, "/tmp", btrfsutil.Snaps[1], read_pipe)
  if !errors.Is(err, mocks.ErrIoPipe) {
    t.Errorf("ReceiveSendStream bad error propagation: %v", err)
  }
}

func buildSnapshotSequence(
    sv *pb.SubVolume, period time.Duration, from time.Time, snap_count int) []*pb.SubVolume {
  var snaps []*pb.SubVolume
  last := from
  for i := 0; i < snap_count; i+=1 {
    snap := util.DummySnapshot(uuid.NewString(), sv.Uuid) 
    snap.CreatedTs = uint64(last.Unix())
    snap.GenAtCreation = snap.CreatedTs
    snap.MountedPath = fpmod.Join("/tmp", snap.TreePath)
    last = last.Add(-period)
    snaps = append(snaps, snap)
  }
  rand.Shuffle(len(snaps), func(i, j int) {
		snaps[i], snaps[j] = snaps[j], snaps[i]
	})
  return snaps
}

func printSnapsWithCreationTs(snaps []*pb.SubVolume) {
  print_snaps := make([]*pb.SubVolume, len(snaps))
  copy(print_snaps, snaps)
  sort.Sort(ByCGen(print_snaps))
  for idx,snap := range print_snaps {
    ctime := time.Unix(int64(snap.CreatedTs), 0)
    util.Debugf("%d. uuid:%s, creation:%s", idx, snap.Uuid, ctime.Format("2006/01/02 15:04"))
  }
}

func expectNInWindow(
    t *testing.T, history *pb.Source_SnapHistory, snaps []*pb.SubVolume, win_idx int, expect int) {
  var found []*pb.SubVolume
  start_recent := time.Now().Add(-24 * time.Duration(history.DaysKeepAll) * time.Hour)
  period := 24 * time.Duration(history.KeepOnePeriodDays) * time.Hour
  period_start := start_recent.Add(-time.Duration(win_idx) * period)
  period_end   := period_start.Add(period)
  for _,snap := range snaps {
    if int64(snap.CreatedTs) >= period_start.Unix() &&
       int64(snap.CreatedTs) < period_end.Unix() {
      found = append(found, snap)
    }
  }
  if len(found) != expect {
    t.Errorf("Expected %d in %s - %s, got %d", expect,
             period_start.Format("2006/01/02 15:04"), period_end.Format("2006/01/02 15:04"), len(found))
    printSnapsWithCreationTs(found)
  }
}

func TestTrimOldSnapshots_NoHistoryConf(t *testing.T) {
  volmgr, _, _ := buildTestManager()
  _, err := volmgr.TrimOldSnapshots(util.DummySubVolume(uuid.NewString()), false)
  if err == nil { t.Fatalf("volmgr.TrimOldSnapshots should have failed") }
}

func TestTrimOldSnapshots_OnlyRecentVols(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  snap_count := volmgr.conf.Sources[0].History.DaysKeepAll - 1

  btrfsutil.Snaps = buildSnapshotSequence(btrfsutil.Subvols[0],
                                          24*time.Hour, time.Now(), int(snap_count))
  expect_len := len(btrfsutil.Snaps)
  del_snaps, err := volmgr.TrimOldSnapshots(btrfsutil.Subvols[0], false)

  if err != nil { t.Fatalf("volmgr.TrimOldSnapshots err:%v", err) }
  if len(del_snaps) > 0 { t.Errorf("Should not have deleted any volume") }
  util.EqualsOrFailTest(t, "Snapshots were deleted", len(btrfsutil.Snaps), expect_len)
}

func TestTrimOldSnapshots_RecentVolsAndOneOld(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  snap_count := volmgr.conf.Sources[0].History.DaysKeepAll + 1

  btrfsutil.Snaps = buildSnapshotSequence(btrfsutil.Subvols[0],
                                          24*time.Hour, time.Now(), int(snap_count))
  expect_len := len(btrfsutil.Snaps)
  del_snaps, err := volmgr.TrimOldSnapshots(btrfsutil.Subvols[0], false)

  if err != nil { t.Fatalf("volmgr.TrimOldSnapshots err:%v", err) }
  if len(del_snaps) > 0 { t.Errorf("Should not have deleted any volume") }
  util.EqualsOrFailTest(t, "Snapshots were deleted", len(btrfsutil.Snaps), expect_len)
}

func TestTrimOldSnapshots_NormalCase(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  h := volmgr.conf.Sources[0].History
  snap_count := h.DaysKeepAll + 3
  expect_len := h.DaysKeepAll + 1
  expect_del := snap_count - expect_len
  most_recent := time.Now().Add(-7*time.Second)

  btrfsutil.Snaps = buildSnapshotSequence(btrfsutil.Subvols[0],
                                          24*time.Hour, most_recent, int(snap_count))
  //printSnapsWithCreationTs(btrfsutil.Snaps)
  del_snaps, err := volmgr.TrimOldSnapshots(btrfsutil.Subvols[0], false)

  if err != nil { t.Fatalf("volmgr.TrimOldSnapshots err:%v", err) }
  util.EqualsOrFailTest(t, "Bad del count", len(del_snaps), expect_del)
  util.EqualsOrFailTest(t, "Not enough snapshots were deleted", len(btrfsutil.Snaps), expect_len)
  expectNInWindow(t, h, btrfsutil.Snaps, 1, 1)
  expectNInWindow(t, h, del_snaps, 1, 2)
}

func TestTrimOldSnapshots_DryRun(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  h := volmgr.conf.Sources[0].History
  snap_count := h.DaysKeepAll + 3
  most_recent := time.Now().Add(-7*time.Second)

  btrfsutil.Snaps = buildSnapshotSequence(btrfsutil.Subvols[0],
                                          24*time.Hour, most_recent, int(snap_count))
  del_snaps, err := volmgr.TrimOldSnapshots(btrfsutil.Subvols[0], true)

  if err != nil { t.Fatalf("volmgr.TrimOldSnapshots err:%v", err) }
  util.EqualsOrFailTest(t, "In dry-run snaps got deleted", len(btrfsutil.Snaps), snap_count)
  printSnapsWithCreationTs(del_snaps)
}

func TestTrimOldSnapshots_ManyPeriods(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  h := volmgr.conf.Sources[0].History
  const period_cnt = 3
  snap_count := h.DaysKeepAll + h.KeepOnePeriodDays * period_cnt
  expect_len := h.DaysKeepAll + period_cnt
  expect_del := snap_count - expect_len
  most_recent := time.Now().Add(-7*time.Second)

  btrfsutil.Snaps = buildSnapshotSequence(btrfsutil.Subvols[0],
                                          24*time.Hour, most_recent, int(snap_count))
  del_snaps, err := volmgr.TrimOldSnapshots(btrfsutil.Subvols[0], false)

  if err != nil { t.Fatalf("volmgr.TrimOldSnapshots err:%v", err) }
  util.EqualsOrFailTest(t, "Bad del count", len(del_snaps), expect_del)
  util.EqualsOrFailTest(t, "Not enough snapshots were deleted", len(btrfsutil.Snaps), expect_len)
  for i:=1; i<=period_cnt; i+=1 {
    expectNInWindow(t, h, btrfsutil.Snaps, i, 1)
    expectNInWindow(t, h, del_snaps, i, int(h.KeepOnePeriodDays) - 1)
  }
}

func TestTrimOldSnapshots_HistoryEqKeepOnePeriod(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  h := volmgr.conf.Sources[0].History
  const period_cnt = 7
  snap_count := h.DaysKeepAll + period_cnt
  expect_len := snap_count
  expect_del := snap_count - expect_len
  most_recent := time.Now().Add(-7*time.Second)
  period := 24 * time.Duration(h.KeepOnePeriodDays) * time.Hour

  btrfsutil.Snaps = buildSnapshotSequence(btrfsutil.Subvols[0],
                                          period, most_recent, int(snap_count))
  del_snaps, err := volmgr.TrimOldSnapshots(btrfsutil.Subvols[0], false)

  if err != nil { t.Fatalf("volmgr.TrimOldSnapshots err:%v", err) }
  util.EqualsOrFailTest(t, "Bad del count", len(del_snaps), expect_del)
  util.EqualsOrFailTest(t, "Not enough snapshots were deleted", len(btrfsutil.Snaps), expect_len)
}

func TestTrimOldSnapshots_SparseHistory(t *testing.T) {
  volmgr, btrfsutil, _ := buildTestManager()
  h := volmgr.conf.Sources[0].History
  h.DaysKeepAll = 3
  h.KeepOnePeriodDays = h.DaysKeepAll
  const snap_count = 8
  const period_mult = 3
  expect_len := snap_count/2 + 1
  expect_del := snap_count - expect_len
  most_recent := time.Now().Add(-7*time.Second)
  period := 24 * time.Duration(period_mult*h.KeepOnePeriodDays) * time.Hour

  btrfsutil.Snaps = buildSnapshotSequence(btrfsutil.Subvols[0],
                                          period, most_recent, int(snap_count/2))
  btrfsutil.Snaps = append(btrfsutil.Snaps,
                           buildSnapshotSequence(btrfsutil.Subvols[0],
                                                 period,
                                                 most_recent.Add(-7*time.Second),
                                                 int(snap_count/2))...)
  del_snaps, err := volmgr.TrimOldSnapshots(btrfsutil.Subvols[0], false)

  if err != nil { t.Fatalf("volmgr.TrimOldSnapshots err:%v", err) }
  util.EqualsOrFailTest(t, "Bad del count", len(del_snaps), expect_del)
  util.EqualsOrFailTest(t, "Not enough snapshots were deleted", len(btrfsutil.Snaps), expect_len)
  for i:=1; i<snap_count/2; i+=1 {
    expectNInWindow(t, h, btrfsutil.Snaps, i*period_mult, 1)
    expectNInWindow(t, h, del_snaps, i*period_mult, 1)
  }
}

