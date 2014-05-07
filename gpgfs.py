#!/usr/bin/env python

from fuse import FUSE, FuseOSError, Operations
import errno
import stat
import os
import sys
import logging
import time
import gpgstore
import sqlite3
from contextlib import contextmanager

log = logging.getLogger('gpgfs')

class Entry:
    '''
    Filesystem object, either file or directory.
    '''
    def __init__(self, **kwargs):
        for k,v in kwargs.iteritems():
            setattr(self, k, v)

class LoggingMixIn:

    def __call__(self, op, path, *args):
        if op=='write':
            atxt = ' '.join([repr(args[0])[:10], repr(args[1]), repr(args[2])])
        else:
            atxt = ' '.join(map(repr, args))
        log.debug('-> %s %s %s', op, repr(path), atxt)
        ret = '[Unhandled Exception]'
        try:
            ret = getattr(self, op)(path, *args)
            return ret
        except OSError, e:
            ret = str(e)
            raise
        finally:
            rtxt = repr(ret)
            if op=='read':
                rtxt = rtxt[:10]
            log.debug('<- %s %s', op, rtxt)

@contextmanager
def transaction(cur, active=True):
    if not active:
        yield
        return
    cur.execute('BEGIN EXCLUSIVE')
    try:
        yield
    except:
        cur.execute('ROLLBACK')
        raise
    try:
        cur.execute('COMMIT')
    except sqlite3.OperationalError:
        log.exception("transaction failed")
        raise FuseOSError(errno.EIO)

class GpgFs(LoggingMixIn, Operations):
#class GpgFs(Operations):

    def __init__(self, encroot, mountpoint, keyid):
        '''
        :param encroot: Encrypted root directory
        '''
        self.encroot = encroot.rstrip('/')
        assert os.path.exists(self.encroot)
        assert os.path.isdir(self.encroot)
        self.store = gpgstore.GpgStore(self.encroot, keyid)
        self.index_path = 'index'
        self.dbpath = '.gpgfs.db'
        self.mountpoint = mountpoint
        self.fd = 0
        self._clear_write_cache()

    def _find(self, path, parent=False, **kwargs):
        assert path.startswith('/')
        names = path[1:].split('/')
        if parent:
            basename = names[-1]
            path = names[:-1]
        sql = 'JOIN entry e{i} ON e{i}.parent_id=e{j}.id AND e{i}.name=?'
        joins = [{i:i+1, j:i} for i in range(len(names))]
        joins = '\n'.join(sql.format(j) for j in joins)
        sql = """
          SELECT e{i}.* FROM entry e0
          {joins}
          WHERE e0.name='' AND e0.parent_id=0
        """.format(joins=joins, i=len(names)-1)
        cur = self.db.execute(sql, names)
        if cur.rowcount != 1:
            if 'default' in kwargs:
                return kwargs['default']
            raise FuseOSError(errno.ENOENT)
        ent = cur.fetchone()
        if parent:
            return ent, basename
        return ent

    def _put(self, path, data, transaction_=True):
        if path[1:] == self.dbpath:
            encpath = self.store.put(data, self.index_path)
        else:
            encpath = self.store.put(data)
        with transaction(self.db, transaction_):
            try:
                ent = self._find(path)
                sql = "UPDATE entry SET size=?, encpath=?, mtime=? WHERE id=?"
                self.db.execute(sql, [len(data), encpath, time.time(), ent.id])
            except:
                self.store.delete(encpath)
                raise
        if ent.encpath != None:
            self.store.delete(ent.encpath)
        return encpath

    def _clear_write_cache(self):
        self.write_path = None
        self.write_buf = []
        self.write_len = 0
        self.write_dirty = False

    def _init_db(self, db):
        sql = """
          CREATE TABLE entry (
            id INT PRIMARY KEY,
            name TEXT NOT NULL,
            parent_id INT NOT NULL,
            encpath TEXT UNIQUE,
            mode INT NOT NULL,
            nlink INT,
            size INT,
            mtime FLOAT,
            ctime FLOAT,
            UNIQUE (name, parent_id),
            FOREIGN KEY(parent_id) REFERENCES entry(id)
          )"""
        db.execute(sql)
        db.execute('BEGIN EXCLUSIVE')
        sql = """
          INSERT INTO entry (id, name, parent_id, mode,
                             nlink, size, mtime, ctime)
          VALUES (?,?,?,?,?,?,?,?)"""
        now = time.time()
        db.execute(sql, [0, '', 0, stat.S_IFDIR | 0755,
                         3, 0, now, now])
        db.execute('COMMIT')

    def init(self, path):
        init = not self.store.exists(self.index_path)
        path = self.mountpoint + '/' + self.dbpath
        log.debug('opening %s', path)
        self.dbconn = sqlite3.connect(path, isolation_level=None)
        self.dbconn.row_factory = sqlite3.Row
        self.db = self.dbconn.cursor()
        if init:
            self._init_db(self.db)
            log.info('created %s', path)

    def destroy(self, path):
        self.db.close()

    def access(self, path, amode):
        self._find(path)
        return 0

    def chmod(self, path, mode):
        # sanitize mode (clear setuid/gid/sticky bits)
        mode &= 0777
        with transaction(self.db):
            ent = self._find(path)
            mode |= (ent.mode & 0170000)
            self.db.execute('UPDATE entry SET mode=? WHERE id=?', [mode, ent.id])
            if not self.db.rowcount:
                raise FuseOSError(errno.ENOENT)

    def chown(self, path, uid, gid):
        raise FuseOSError(errno.ENOSYS)

    def create(self, path, mode):
        mode &= 0777
        mode |= stat.S_IFREG
        with transaction(self.db):
            parent, name = self._find(path, parent=True)
            sql = """
              INSERT INTO entry (name, parent_id, mode, nlink, ctime)
              VALUES (?,?,?,?,?)
            """
            now = time.time()
            try:
                self.db.execute(sql, [name, parent.id, mode, 1, now])
            except sqlite3.IntegrityError:
                raise FuseOSError(errno.EEXIST)
            self._put(path, '', transaction_=False)
            sql = "UPDATE entry SET mtime=? WHERE id=?"
            self.db.execute(sql, [now, parent.id])
            self.fd += 1
            return self.fd

    def flush(self, path, fh):
        if not self.write_dirty:
            log.debug('nothing to flush')
            return 0
        buf = ''.join(self.write_buf)
        self.write_buf = [buf]
        self._put(self.write_path, buf)
        self.write_dirty = False
        log.debug('flushed %d bytes to %s', len(buf), self.write_path)
        return 0

    def fsync(self, path, datasync, fh):
        self.flush(path, fh)
        return 0

    def getattr(self, path, fh = None):
        with transaction(self.db):
            ent = self._find(path)
            return dict(st_mode = ent.mode, st_size = ent.size,
                        st_ctime = ent.ctime, st_mtime = ent.mtime,
                        st_atime = 0, st_nlink = ent.nlink)

    def getxattr(self, path, name, position = 0):
        raise FuseOSError(errno.ENODATA) # ENOATTR

    def listxattr(self, path):
        return []

    def mkdir(self, path, mode):
        mode &= 0777
        mode |= stat.S_IFDIR
        with transaction(self.db):
            parent, name = self._find(path, parent=True)
            sql = """
              INSERT INTO entry
                (name, type, parent_id, mode, nlink, size, mtime, ctime)
              VALUES (?,?,?,?,?,?,?,?)
            """
            now = time.time()
            try:
                self.db.execute(sql, [name, parent.id,
                                      mode, 2, 0, now, now])
            except sqlite3.IntegrityError:
                raise FuseOSError(errno.EEXIST)
            sql = "UPDATE entry SET mtime=? WHERE id=?"
            self.db.execute(sql, [now, parent.id])

    def open(self, path, flags):
        return 0

    def read(self, path, size, offset, fh):
        self.flush(path, 0)
        ent = self._find(path)
        assert ent.mode & stat.S_IFREG
        try:
            data = self.store.get(ent.encpath)
        except IOError:
            raise FuseOSError(errno.ENOENT)
        return data[offset:offset + size]

    def readdir(self, path, fh):
        dirent = self._find(path)
        sql = "SELECT name FROM entry WHERE parent_id=?"
        self.db.execute(sql, [dirent.id])
        return ['.', '..'] + [name for name, in self.db]

    def readlink(self, path):
        raise FuseOSError(errno.ENOSYS)

    def removexattr(self, path, name):
        raise FuseOSError(errno.ENOSYS)

    def rename(self, old, new):
        self.flush(old, 0)
        self._clear_write_cache()
        if new.startswith(old):
            raise FuseOSError(errno.EINVAL)
        with transaction(self.db):
            old_ent = self._find(old)
            new_ent = self._find(new, default=None)
            old_parent, old_name = self._find(old, parent=True)
            new_parent, new_name = self._find(new, parent=True)
            if new_ent != None:
                if new_ent.mode & stat.S_IFDIR:
                    if not old_ent.mode & stat.S_IFDIR:
                        raise FuseOSError(errno.EISDIR)
                    sql = "SELECT COUNT(*) FROM entry WHERE parent_id=?"
                    self.db.execute(sql, [new_ent.id])
                    if self.db.fetchone()[0]:
                        raise FuseOSError(errno.ENOTEMPTY)
                elif old_ent.mode & stat.S_IFDIR:
                    raise FuseOSError(errno.ENOTDIR)
                sql = "DELETE FROM entry WHERE id=?"
                self.db.execute(sql, [new_ent.id])
            sql = "UPDATE entry SET parent_id=? WHERE id=?"
            self.db.execute(sql, [new_parent.id, old_ent.id])
            sql = "UPDATE entry SET mtime=? WHERE id IN (?,?)"
            self.db.execute(sql, [time.time(), old_parent.id, new_parent.id])
        if new_ent != None and new_ent.mode & stat.S_IFREG:
            self.store.delete(new_ent.encpath)

    def rmdir(self, path):
        with transaction(self.db):
            ent = self._find(path)
            if not ent.mode & stat.S_IFDIR:
                raise FuseOSError(errno.ENOTDIR)
            sql = "SELECT COUNT(*) FROM entry WHERE parent_id=?"
            self.db.execute(sql, [ent.id])
            if self.db.fetchone()[0]:
                raise FuseOSError(errno.ENOTEMPTY)
            sql = "DELETE FROM entry WHERE id=?"
            self.db.execute(sql, [ent.id])
            sql = "UPDATE entry SET mtime=? WHERE id=?"
            self.db.execute(sql, [time.time(), ent.parent_id])

    def setxattr(self, path, name, value, options, position = 0):
        raise FuseOSError(errno.ENOSYS)

    def statfs(self, path):
        raise FuseOSError(errno.ENOSYS)

    def symlink(self, target, source):
        raise FuseOSError(errno.ENOSYS)

    def truncate(self, path, length, fh = None):
        self.flush(path, 0)
        self._clear_write_cache()
        with transaction(self.db):
            ent = self._find(path)
            if length == 0:
                buf = ''
            else:
                buf = self.store.get(ent.encpath)
                buf = buf[:length]
            self._put(path, buf, transaction_=False)

    def unlink(self, path):
        with transaction(self.db):
            if self.write_path == path:
                # no need to flush afterwards
                self._clear_write_cache()
            ent = self._find(path)
            sql = "DELETE FROM entry WHERE id=?"
            self.db.execute(sql, [ent.id])
            sql = "UPDATE entry SET mtime=? WHERE id=?"
            self.db.execute(sql, [time.time(), ent.parent_id])
        self.store.delete(ent.encpath)

    def utimens(self, path, times = None):
        if times is None:
            mtime = time.time()
        else:
            mtime = times[1]
        with transaction(self.db):
            ent = self._find(path)
            sql = "UPDATE entry SET mtime=? WHERE id=?"
            self.db.execute(sql, [mtime, ent.id])

    def write(self, path, data, offset, fh):
        if path != self.write_path:
            self.flush(self.write_path, None)
            ent = self._find(path)
            buf = self.store.get(ent.encpath)
            self.write_buf = [buf]
            self.write_len = len(buf)
        self.write_path = path
        if offset == self.write_len:
            self.write_buf.append(data)
            self.write_len += len(data)
        else:
            buf = ''.join(self.write_buf)
            buf = buf[:offset] + data + buf[offset + len(data):]
            self.write_buf = [buf]
            self.write_len = len(buf)
        self.write_dirty = True
        return len(data)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.stderr.write('Usage: gpgfs <gpg_keyid> <encrypted_root> <mountpoint>\n')
        sys.exit(1)
    logpath = os.path.join(os.path.dirname(__file__), 'gpgfs.log')
    log.addHandler(logging.FileHandler(logpath, 'w'))
    log.setLevel(logging.DEBUG)
    fs = GpgFs(sys.argv[2], sys.argv[3], sys.argv[1])
    FUSE(fs, sys.argv[3], foreground=True)
