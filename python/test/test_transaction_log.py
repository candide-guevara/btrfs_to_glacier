import unittest as ut
from common import *
from routines_for_test import *
from transaction_log import *
from txlog_consistency import *
from txlog_manipulation import *
logger = logging.getLogger(__name__)

@deco_setup_each_test
class TestBackupFiles (ut.TestCase):
  
  #@ut.skip("For quick validation")
  def test_silly_coverage_cases (self):
    assert get_txlog().is_empty()
    # the hash validation should not fail for an empty file
    get_txlog()._validate_main_hash_or_die(b'', 0)
    self.assertTrue( repr(get_txlog()) )
    self.assertEqual( 0, len(get_txlog()) )
    self.assertEqual( sum(1 for i in get_txlog().iterate_through_records()), 
                      sum(1 for i in get_txlog().reverse_iterate_through_records()) )

    add_fake_backup_to_txlog()
    self.assertTrue( repr(get_txlog()) )
    self.assertTrue( len(get_txlog()) > 0 )
    self.assertTrue( len(get_txlog()) > 0 )
    self.assertEqual( sum(1 for i in get_txlog().iterate_through_records()), 
                      sum(1 for i in get_txlog().reverse_iterate_through_records()) )

  #@ut.skip("For quick validation")
  def test_txlog_unencrypted_backup_restore (self):
    add_fake_backup_to_txlog()
    fileout = get_txlog().backup_to_crypted_file()
    clean_tx_log()
    TransactionLog.restore_from_crypted_file(fileout)
    record_type_count = calculate_record_type_count()
    self.assertEqual(4, record_type_count[Record.NEW_SNAP])
    self.assertEqual(4, record_type_count[Record.SNAP_TO_FILE])
    self.assertEqual(2, record_type_count[Record.DEL_SNAP])

  #@ut.skip("For quick validation")
  def test_txlog_encrypted_backup_restore (self):
    get_conf().app.encrypt = True
    self.test_txlog_unencrypted_backup_restore()

  #@ut.skip("For quick validation")
  def test_main_hash_protection (self):
    add_fake_backup_to_txlog()
    add_fake_restore_to_txlog()
    get_txlog().calculate_and_store_txlog_hash()
    filein = get_conf().app.transaction_log
    with open(filein, 'rb') as fileobj:
      main_hash, hash_domain_upper = TransactionLog.parse_header_and_advance_file(fileobj)
    modif_range = (TransactionLog.HEADER_LEN, TransactionLog.HEADER_LEN + hash_domain_upper)

    for i in range(10):
      corrupt_file = modify_random_byte_in_file(filein, modif_range[0], modif_range[1])
      get_conf().app.transaction_log = corrupt_file
      reset_txlog()
      with self.assertRaises(Exception):
        logger.warning("Loaded a corrupt tx log = %r", get_txlog())

  #@ut.skip("For quick validation")
  def test_recorded_snaps_and_restores (self):
    self.assertEqual(0, len(get_txlog().recorded_snaps))
    self.assertEqual(0, len(get_txlog().recorded_restores))
    add_fake_backup_to_txlog()
    add_fake_restore_to_txlog()
    self.assertEqual(4, len(get_txlog().recorded_snaps))
    self.assertEqual(4, len(get_txlog().recorded_restores))

### END TestTransactionLog

@deco_setup_each_test
class TestTxLogChecker (ut.TestCase):

  #@ut.skip("For quick validation")
  def test_overlap_check (self):
    ov_check = OverlapChecker()
    self.assertTrue(not ov_check.pending_back_session and ov_check.complete_back_session == 0)
    self.assertTrue(not ov_check.pending_upld_session and ov_check.complete_upld_session == 0)
    self.assertTrue(not ov_check.pending_down_session and ov_check.complete_down_session == 0)
    self.assertTrue(not ov_check.pending_rest_session and ov_check.complete_rest_session == 0)

    ov_check = OverlapChecker()
    add_fake_backup_to_txlog  (with_session=True)
    add_fake_upload_to_txlog  (with_session=True)
    add_fake_download_to_txlog(with_session=True)
    add_fake_restore_to_txlog (with_session=True)

    for r in get_txlog().iterate_through_records():
      ov_check.next_record(r)
    self.assertTrue(not ov_check.pending_back_session and ov_check.complete_back_session == 1)
    self.assertTrue(not ov_check.pending_upld_session and ov_check.complete_upld_session == 1)
    self.assertTrue(not ov_check.pending_down_session and ov_check.complete_down_session == 1)
    self.assertTrue(not ov_check.pending_rest_session and ov_check.complete_rest_session == 1)

    ov_check = OverlapChecker()
    with self.assertRaises(Exception):
      for r in get_txlog().reverse_iterate_through_records():
        ov_check.next_record(r)

    clean_tx_log()
    ov_check = OverlapChecker()
    get_txlog().record_aws_session_start(Record.SESSION_DOWN)
    get_txlog().record_backup_start()
    with self.assertRaises(Exception):
      for r in get_txlog().iterate_through_records():
        ov_check.next_record(r)

  #@ut.skip("For quick validation")
  def test_check_log_for_backup (self):
    vol1 = DummyBtrfsNode.build()
    snap1 = DummyBtrfsNode.snap(vol1)
    snap11 = DummyBtrfsNode.snap(vol1)

    # empty tx log = ok
    TxLogConsistencyChecker.check_log_for_backup(get_txlog().iterate_through_records())

    # After a previous backup = ok
    add_fake_backup_to_txlog(with_session=True)
    TxLogConsistencyChecker.check_log_for_backup(get_txlog().iterate_through_records())

    # After a backup outside a session = ko
    add_fake_backup_to_txlog(with_session=False)
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_backup(get_txlog().iterate_through_records())

    # Last session not closed
    clean_tx_log()
    get_txlog().record_backup_start()
    add_fake_backup_to_txlog(with_session=False)
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_backup(get_txlog().iterate_through_records())

    # Operation on a snapshot whose parent is not known
    clean_tx_log()
    get_txlog().record_backup_start()
    fake_backup_file_tx('fs1', snap11, vol1)
    get_txlog().record_backup_end()
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_backup(get_txlog().iterate_through_records())

    # Send file from a snapshot outside session
    clean_tx_log()
    get_txlog().record_backup_start()
    # we create record snap1 to add vol1 in the list of subvolumes checked
    get_txlog().record_snap_creation(snap1)
    fake_backup_file_tx('fs12', snap11, vol1)
    get_txlog().record_backup_end()
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_backup(get_txlog().iterate_through_records())

    # Deleted snapshot outside of session
    clean_tx_log()
    get_txlog().record_backup_start()
    get_txlog().record_subvol_delete(snap11)
    get_txlog().record_backup_end()
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_backup(get_txlog().iterate_through_records())

    # Snap created but not saved to a file
    clean_tx_log()
    get_txlog().record_backup_start()
    get_txlog().record_snap_creation(snap1)
    get_txlog().record_backup_end()
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_backup(get_txlog().iterate_through_records())

    # Send file writen after deletion
    clean_tx_log()
    get_txlog().record_backup_start()
    get_txlog().record_snap_creation(snap1)
    get_txlog().record_subvol_delete(snap1)
    fake_backup_file_tx('fs12', snap11, vol1)
    get_txlog().record_backup_end()
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_backup(get_txlog().iterate_through_records())

  #@ut.skip("For quick validation")
  def test_check_log_for_restore (self):
    # Empty txlog nothing to restore = ok
    TxLogConsistencyChecker.check_log_for_restore(get_txlog().iterate_through_records())

    # Completed download session previously
    clean_tx_log()
    get_txlog().record_aws_session_start(Record.SESSION_DOWN)
    get_txlog().record_aws_session_end(Record.SESSION_DOWN)
    TxLogConsistencyChecker.check_log_for_restore(get_txlog().iterate_through_records())

    # Incompleted download session previously
    get_txlog().record_aws_session_start(Record.SESSION_DOWN)
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_restore(get_txlog().iterate_through_records())

    # Restore operations recorded outside of session
    add_fake_restore_to_txlog(with_session=False)
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_restore(get_txlog().iterate_through_records())

    # Only 1 restore per transaction log
    clean_tx_log()
    add_fake_restore_to_txlog(with_session=True)
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_restore(get_txlog().iterate_through_records())

  #@ut.skip("For quick validation")
  def test_check_log_for_upload (self):
    fs1 = Fileseg.build_from_fileout(get_conf().app.staging_dir + '/fs1', (0,2048))
    fs1.aws_id = 'multipart_upload_id1'
    fs2 = Fileseg.build_from_fileout(get_conf().app.staging_dir + '/fs2', (0,1024))
    fs2.aws_id = 'multipart_upload_id2'

    # Empty txlog nothing to upload = ok
    TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Previous backup session completed = ok
    add_fake_backup_to_txlog(with_session=True)
    TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Previous upload session completed but no previous backup = ok
    clean_tx_log()
    add_fake_upload_to_txlog(with_session=True)
    TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Previous upload session completed with some snaps from previous backup = ok
    clean_tx_log()
    add_fake_backup_to_txlog(with_session=True)
    add_fake_upload_to_txlog(with_session=True)
    TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Resuming from previous pending upload
    clean_tx_log()
    get_txlog().record_aws_session_start(Record.SESSION_UPLD)
    add_fake_upload_to_txlog(with_session=False)
    TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Resuming from previous pending upload, unfinished fileseg
    clean_tx_log()
    get_txlog().record_aws_session_start(Record.SESSION_UPLD)
    get_txlog().record_fileseg_start(fs1)
    TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Resuming from previous pending upload, unfinished fileseg with chunks
    clean_tx_log()
    get_txlog().record_aws_session_start(Record.SESSION_UPLD)
    get_txlog().record_fileseg_start(fs1)
    get_txlog().record_chunk_end([0,1024])
    TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Resuming from previous pending upload, double multipart upload for same fileseg
    clean_tx_log()
    get_txlog().record_aws_session_start(Record.SESSION_UPLD)
    add_fake_upload_to_txlog(with_session=False)
    get_txlog().record_fileseg_start(fs1)
    get_txlog().record_fileseg_start(fs1)
    TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Resuming from previous pending upload, double multipart upload for same fileseg with chunks
    clean_tx_log()
    get_txlog().record_aws_session_start(Record.SESSION_UPLD)
    add_fake_upload_to_txlog(with_session=False)
    get_txlog().record_fileseg_start(fs1)
    get_txlog().record_chunk_end([0,1024])
    get_txlog().record_fileseg_start(fs1)
    get_txlog().record_chunk_end([0,1024])
    get_txlog().record_chunk_end([1024,2048])
    TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Operations outside of session boundary
    clean_tx_log()
    get_txlog().record_fileseg_end('surprise_mf')
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Pending backup session
    clean_tx_log()
    add_fake_backup_to_txlog(with_session=True)
    get_txlog().record_backup_start()
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Overlapping backup and upload sessions
    clean_tx_log()
    get_txlog().record_aws_session_start(Record.SESSION_UPLD)
    get_txlog().record_backup_end()
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

    # Past send file was not uploaded
    clean_tx_log()
    add_fake_backup_to_txlog(with_session=True)
    get_txlog().record_aws_session_start(Record.SESSION_UPLD)
    get_txlog().record_fileseg_start(fs2)
    get_txlog().record_fileseg_end('archive_id_2')
    get_txlog().record_aws_session_end(Record.SESSION_UPLD)
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())


  #@ut.skip("For quick validation")
  def test_check_log_for_download (self):
    fs1 = Fileseg.build_from_fileout(get_conf().app.staging_dir + '/fs1', (0,2048))
    fs1.aws_id = 'multipart_upload_id1'

    # Empty txlog nothing to download = ok
    TxLogConsistencyChecker.check_log_for_download(get_txlog().iterate_through_records())

    # Previous upload session completed = ok
    clean_tx_log()
    add_fake_upload_to_txlog(with_session=True)
    TxLogConsistencyChecker.check_log_for_download(get_txlog().iterate_through_records())

    # Operations outside of session boundary
    clean_tx_log()
    get_txlog().record_fileseg_end('surprise_mf')
    with self.assertRaises(Exception):
      TxLogConsistencyChecker.check_log_for_upload(get_txlog().iterate_through_records())

  #@ut.skip("For quick validation")
  def test_per_restore_batch_hash_protection (self):
    for i in range(3):
      add_fake_backup_to_txlog()
      hashstr = get_txlog().calculate_and_store_txlog_hash()
      get_txlog()._record_txlog_to_file(hashstr)
    TxLogConsistencyChecker._validate_all_individual_batch_hashes(get_txlog().logfile)
    
    for j in range(3):
      clean_tx_log()
      change_timestamp()

      for i in range(3):
        add_fake_backup_to_txlog()
        hashstr = get_txlog().calculate_and_store_txlog_hash()
        get_txlog()._record_txlog_to_file(hashstr)
        if i == j:
          get_txlog()._record_txlog_to_file(hashstr + b"|oops")
        else:
          get_txlog()._record_txlog_to_file(hashstr)

      with self.assertRaises(Exception):
        TxLogConsistencyChecker._validate_all_individual_batch_hashes(get_txlog().logfile)

### END TestTxLogChecker

@deco_setup_each_test
class TestTxManipulation (ut.TestCase):

  #@ut.skip("For quick validation")
  def test_avoid_overwrite (self):
    add_fake_backup_to_txlog(with_session=True)
    src_txlog_path = get_conf().app.transaction_log
    dest_txlog_path = give_stage_filepath()

    dest_txlog = TxLogManipulation.remove_upload_sessions(src_txlog_path, dest_txlog_path)
    with self.assertRaises(Exception):
      TxLogManipulation.remove_upload_sessions(src_txlog_path, dest_txlog_path)

  #@ut.skip("For quick validation")
  def test_remove_intermediate_hashes (self):
    add_fake_backup_to_txlog(with_session=True)
    get_txlog().backup_to_crypted_file()
    add_fake_backup_to_txlog(with_session=True)
    get_txlog().backup_to_crypted_file()
    src_txlog_path = get_conf().app.transaction_log
    dest_txlog_path = give_stage_filepath()

    dest_txlog = TxLogManipulation.remove_upload_sessions(src_txlog_path, dest_txlog_path)
    self.assertEqual( len(get_txlog()) - 2, len(dest_txlog) )

  #@ut.skip("For quick validation")
  def test_manipulate_empty_txlog (self):
    src_txlog_path = get_conf().app.transaction_log
    dest_txlog_path = give_stage_filepath()

    with self.assertRaises(Exception):
      dest_txlog = TxLogManipulation.remove_upload_sessions(src_txlog_path, dest_txlog_path)

  #@ut.skip("For quick validation")
  def test_remove_upload_sessions (self):
    add_fake_backup_to_txlog(with_session=True)

    src_txlog_path = get_conf().app.transaction_log
    dest_txlog_path = give_stage_filepath()

    dest_txlog = TxLogManipulation.remove_upload_sessions(src_txlog_path, dest_txlog_path)
    self.assertEqual( len(get_txlog()), len(dest_txlog) )

    add_fake_upload_to_txlog(with_session=True)
    add_fake_download_to_txlog(with_session=True)
    add_fake_upload_to_txlog(with_session=True)
    get_txlog().record_aws_session_start(Record.SESSION_UPLD)
    add_fake_upload_to_txlog(with_session=False)
    dest_txlog_path = give_stage_filepath()
    dest_txlog = TxLogManipulation.remove_upload_sessions(src_txlog_path, dest_txlog_path)

    record_type_count = calculate_record_type_count(dest_txlog)
    self.assertEqual( len(get_txlog()) - 2*8 - 7, len(dest_txlog) )
    self.assertEqual(1, record_type_count.get(Record.AWS_START, 0) )
    self.assertEqual(2, record_type_count.get(Record.FILESEG_START, 0) )

  #@ut.skip("For quick validation")
  def test_remove_restore_sessions (self):
    # there is an assertion on txlog checking we do nto restore more than we backup
    add_fake_backup_to_txlog(with_session=True)
    add_fake_backup_to_txlog(with_session=True)
    add_fake_backup_to_txlog(with_session=True)

    src_txlog_path = get_conf().app.transaction_log
    dest_txlog_path = give_stage_filepath()

    dest_txlog = TxLogManipulation.remove_restore_sessions(src_txlog_path, dest_txlog_path)
    self.assertEqual( len(get_txlog()), len(dest_txlog) )

    add_fake_upload_to_txlog(with_session=True)
    add_fake_download_to_txlog(with_session=True)
    add_fake_restore_to_txlog(with_session=True)
    get_txlog().record_restore_start()
    add_fake_restore_to_txlog(with_session=False)
    dest_txlog_path = give_stage_filepath()
    dest_txlog = TxLogManipulation.remove_restore_sessions(src_txlog_path, dest_txlog_path)

    record_type_count = calculate_record_type_count(dest_txlog)
    self.assertEqual( len(get_txlog()) - 8 - 7, len(dest_txlog), "\n%r\n\n%r" % (get_txlog(), dest_txlog) )
    self.assertEqual(0, record_type_count.get(Record.REST_START, 0) )
    self.assertEqual(0, record_type_count.get(Record.FILE_TO_SNAP, 0) )

  #@ut.skip("For quick validation")
  def test_remove_download_sessions (self):
    add_fake_backup_to_txlog(with_session=True)

    src_txlog_path = get_conf().app.transaction_log
    dest_txlog_path = give_stage_filepath()

    dest_txlog = TxLogManipulation.remove_download_sessions(src_txlog_path, dest_txlog_path)
    self.assertEqual( len(get_txlog()), len(dest_txlog) )

    add_fake_download_to_txlog(with_session=True)
    add_fake_backup_to_txlog(with_session=True)
    add_fake_download_to_txlog(with_session=True)
    get_txlog().record_aws_session_start(Record.SESSION_DOWN)
    add_fake_download_to_txlog(with_session=False)
    dest_txlog_path = give_stage_filepath()
    dest_txlog = TxLogManipulation.remove_download_sessions(src_txlog_path, dest_txlog_path)

    record_type_count = calculate_record_type_count(dest_txlog)
    self.assertEqual( len(get_txlog()) - 2*8 - 7, len(dest_txlog) )
    self.assertEqual(0, record_type_count.get(Record.AWS_START, 0) )
    self.assertEqual(0, record_type_count.get(Record.FILESEG_START, 0) )

  #@ut.skip("For quick validation")
  def test_remove_all_records (self):
    add_fake_download_to_txlog(with_session=True)

    src_txlog_path = get_conf().app.transaction_log
    dest_txlog_path = give_stage_filepath()

    dest_txlog = TxLogManipulation.remove_download_sessions(src_txlog_path, dest_txlog_path)
    self.assertEqual( 0, len(dest_txlog) )

### END TestTxManipulation

if __name__ == "__main__":
  conf_for_test()
  ut.main()

