import unittest as ut
import sys, os, pybtrfs, pickle, struct
from btrfs_subvol_list import *
from common import *
logger = logging.getLogger(__name__)

class TestPyBtrfs (ut.TestCase):

  def check_empty_subvol(self, subvol):
    self.assertIsNone(subvol.name)
    self.assertIsNone(subvol.path)
    self.assertIsNone(subvol.uuid)
    self.assertIsNone(subvol.puuid)
    self.assertIsNone(subvol.creation_utc)

  def check_subvol_equal(self, right, left):
    self.assertEqual(right.name,          left.name)
    self.assertEqual(right.path,          left.path)
    self.assertEqual(right.uuid,          left.uuid)
    self.assertEqual(right.puuid,         left.puuid)
    self.assertEqual(right.puuid,         left.puuid)
    self.assertEqual(right.creation_utc,  left.creation_utc)

  def test_create_empty_node(self):
    node = pybtrfs.BtrfsNode()
    logger.debug( "empty node = '%r'", node )
    self.check_empty_subvol(node)

  def test_subvol_pickle_empty(self):
    node = pybtrfs.BtrfsNode()
    ser = pickle.dumps(node)
    clone = pickle.loads(ser)
    self.check_empty_subvol(clone)

  def test_subvol_packer(self):
    subvols = pybtrfs.build_subvol_list( get_conf().test.btrfs_path )
    self.assertTrue(len(subvols) > 0)
    for subvol in subvols:
      ser = pybtrfs.pack_subvol_c_struct(subvol)
      tup = struct.unpack(pybtrfs.PICKLE_FORMAT, ser)
      self.assertTrue(len(tup) > 0)
      #print "\n%r => %r => %r\n" % (subvol, ser, tup)

  def test_create_subvol_tree(self):
    subvols = pybtrfs.build_subvol_list( get_conf().test.btrfs_path )
    logger.debug( "subvolume list = %r", subvols )
    self.assertTrue(len(subvols) > 0)
    self.assertTrue(all( n.name for n in subvols ))

  def test_check_for_snap_in_tree(self):
    subvols = pybtrfs.build_subvol_list( get_conf().test.btrfs_path )
    is_snap = dict( (n.name, n.is_snapshot()) for n in subvols )
    logger.debug( "snapshot dict = %r", is_snap )
    self.assertTrue(len(subvols) > 0)
    self.assertTrue(any( is_snap.values() ))

  def test_subvol_list_wrapper(self):
    subvols = BtrfsSubvolList( get_conf().test.btrfs_path )
    logger.debug( "subvolume list :\n%r", subvols )
    self.assertTrue(len(subvols.subvols) > 0)
    self.assertTrue(all( n.uuid for n in subvols.subvols ))

  def test_subvol_pickle_with_data(self):
    subvols = pybtrfs.build_subvol_list( get_conf().test.btrfs_path )
    self.assertTrue(len(subvols) > 0)
    for subvol in subvols:
      ser = pickle.dumps(subvol)
      clone = pickle.loads(ser)
      self.check_subvol_equal(subvol, clone)

### END TestPyBtrfs

if __name__ == "__main__":
  ut.main()

