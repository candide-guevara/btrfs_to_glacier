from common import *
import pybtrfs

# Shim between btrfs c python module and regular python code
class BtrfsSubvolList (list):

  @staticmethod
  def get_subvols_from_filesystem(btrfs_path):
    subvol_list = BtrfsSubvolList()
    with setuserid.PriviledgeGuard():
      subvol_list.extend( pybtrfs.build_subvol_list(btrfs_path) )
    assert subvol_list
    return subvol_list

  @staticmethod
  def find_by_ruuid(btrfs_path, ruuid):
    subvols = BtrfsSubvolList.get_subvols_from_filesystem(btrfs_path)
    return next((n for n in subvols if n.ruuid == ruuid), None)

  def get_by_ruuid(self, ruuid):
    return next((n for n in self if n.ruuid == ruuid), None)

  def get_by_puuid(self, puuid):
    return next((n for n in self if n.puuid == puuid), None)

  def get_by_uuid(self, uuid):
    return next((n for n in self if n.uuid == uuid), None)

  def get_by_path(self, path):
    return next((n for n in self if n.path == path), None)

  def get_main_subvols(self):
    return [ n for n in self if not n.is_snapshot() and not n.ruuid ]

  def get_readonly_subvols(self):
    return [ n for n in self if n.is_readonly() ]

  def get_snap_childs(self, subvol):
    snaps = [ n for n in self if n.is_snapshot() and n.puuid == subvol.uuid ]
    snaps = sorted(snaps, key=(lambda x: x.creation_utc))
    return snaps

  def __repr__ (self):
    return "\n".join( repr(n) for n in self )

### END BtrfsSubvolList
