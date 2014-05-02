#!/usr/bin/env python

from fuse import FUSE, FuseOSError, Operations
import gnupg # python-gnupg
import zlib
import errno
import stat
from binascii import hexlify
import os
import sys
import logging
import struct
import time
from cStringIO import StringIO

magic = 'GPGFS1\n'

log = logging.getLogger(__name__)

def decrypt(gpg, path):
    try:
        data = file(path).read()
    except IOError, err:
        log.error("read failed: %s: %s", path, str(err))
        raise FuseOSError(err.errno)
    if not data:
        return data
    res = gpg.decrypt(data)
    if not res.ok:
        log.error("decryption failed, %s: %s", res.status, path)
        raise FuseOSError(errno.EIO)
    data = zlib.decompress(res.data)
    log.debug('decrypted %s' % path)
    return data

def encrypt(gpg, keyid, path, data):
    data = zlib.compress(data, 1)
    res = gpg.encrypt(data, keyid, armor=False)
    if not res.ok:
        log.error("encryption failed (keyid %s), %s: %s",
                  keyid, res.status, path)
        raise FuseOSError(errno.EIO)
    try:
        with file(path+'.tmp', 'w') as fd:
            fd.write(res.data)
        os.rename(path+'.tmp', path)
    except IOError, err:
        log.error("write failed: %s: %s", path, str(err))
        raise FuseOSError(err.errno)
    finally:
        try: os.remove(path+'.tmp')
        except: pass
    log.debug('encrypted %s' % path)

class Entry:
    '''
    Filesystem object, either file or directory.
    '''
    def __init__(self, **kwargs):
        for k,v in kwargs.iteritems():
            setattr(self, k, v)

# entry types:
ENT_FILE = 0
ENT_DIR = 1

def read_index(gpg, path):
    data = decrypt(gpg, path)
    buf = StringIO(data)
    if buf.read(len(magic)) != magic:
        raise IOError, 'index parse error: %s' % path
    read_atom(buf)
    root = Entry(**read_dict(buf))
    return root

def write_index(gpg, keyid, path, root):
    buf = StringIO()
    buf.write(magic)
    header = ''
    write_atom(buf, header)
    write_dict(buf, root)
    encrypt(gpg, keyid, path, buf.getvalue())

def write_dict(fd, dct):
    # breadth-first
    children = []
    buf = StringIO()
    if not isinstance(dct, dict):
        dct = dct.__dict__
    for key in dct:
        write_atom(buf, key.encode('utf8'))
        val = dct[key]
        if isinstance(val, dict):
            buf.write('D')
            children.append(val)
        elif isinstance(val, Entry):
            buf.write('E')
            children.append(val)
        elif isinstance(val, (int, long)):
            buf.write('I')
            buf.write(struct.pack('<I', val))
        elif isinstance(val, str):
            buf.write('S')
            write_atom(buf, val)
        elif isinstance(val, unicode):
            buf.write('U')
            write_atom(buf, val.encode('utf8'))
        else:
            raise TypeError, type(val)
    write_atom(fd, buf.getvalue())
    for c in children:
        write_dict(fd, c)

def read_dict(fd):
    dct = {}
    buf = read_atom(fd)
    buflen = len(buf)
    buf = StringIO(buf)
    while buf.tell() < buflen:
        key = read_atom(buf).decode('utf8')
        tag = buf.read(1)
        if tag == 'D':    val = read_dict(fd)
        elif tag == 'E':  val = Entry(**read_dict(fd))
        elif tag == 'I':  val = struct.unpack('<I', buf.read(4))[0]
        elif tag == 'S':  val = read_atom(buf)
        elif tag == 'U':  val = read_atom(buf).decode('utf8')
        else:             raise TypeError, tag
        dct[key] = val
    return dct

def write_atom(fd, atom):
    assert isinstance(atom, str)
    fd.write(struct.pack('<I', len(atom)))
    fd.write(atom)

def read_atom(fd):
    return fd.read(struct.unpack('<I', fd.read(4))[0])

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

class GpgFs(LoggingMixIn, Operations):
#class GpgFs(Operations):

    def __init__(self, encroot, keyid):
        '''
        :param encroot: Encrypted root directory
        '''
        self.encroot = encroot.rstrip('/')
        assert os.path.exists(self.encroot)
        assert os.path.isdir(self.encroot)
        self.keyid = keyid
        #self.cache = cache
        self.gpg = gnupg.GPG()
        self.index_path = self.encroot + '/index'
        if os.path.exists(self.index_path):
            self.root = read_index(self.gpg, self.index_path)
        else:
            self.root = Entry(type=ENT_DIR, children={},
                              st_mode=0755,
                              st_mtime=int(time.time()),
                              st_ctime=int(time.time()))
            self._write_index()
            log.info('created %s', self.index_path)
        self.fd = 0
        self._clear_write_cache()

    def _write_index(self, suffix=''):
        write_index(self.gpg, self.keyid, self.index_path + suffix, self.root)

    def _find(self, path, parent=False):
        assert path.startswith('/')
        if path == '/':
            return self.root
        node = self.root
        path = path[1:].split('/')
        if parent:
            basename = path[-1]
            path = path[:-1]
        for name in path:
            if name not in node.children:
                raise FuseOSError(errno.ENOENT)
            node = node.children[name]
        if parent:
            return node, basename
        return node

    def _clear_write_cache(self):
        self.write_path = None
        self.write_buf = []
        self.write_len = 0
        self.write_dirty = False

    def chmod(self, path, mode):
        # sanitize mode (clear setuid/gid/sticky bits)
        mode &= 0777
        ent = self._find(path)
        if ent.type == ENT_DIR:
            prev_mode = ent.st_mode
            ent.st_mode = mode
            try:
                self._write_index()
            except:
                ent.st_mode = prev_mode
                raise
        else:
            encpath = self.encroot + '/' + ent.path
            os.chmod(encpath, mode)

    def chown(self, path, uid, gid):
        raise FuseOSError(errno.ENOSYS)

    def create(self, path, mode):
        encpath = hexlify(os.urandom(20))
        encpath = encpath[:2] + '/' + encpath[2:]
        dir, path = self._find(path, parent=True)
        if path in dir.children:
            raise FuseOSError(errno.EEXIST)
        encdir = self.encroot + '/' + encpath[:2]
        if not os.path.exists(encdir):
            os.mkdir(encdir, 0755)
        fd = os.open(self.encroot + '/' + encpath,
                     os.O_WRONLY | os.O_CREAT, mode & 0777)
        os.close(fd)
        prev_mtime = dir.st_mtime
        dir.children[path] = Entry(type=ENT_FILE, path=encpath, st_size=0)
        log.debug('new path %s => %s', path, encpath)
        dir.st_mtime = int(time.time())
        try:
            self._write_index()
        except:
            try: os.remove(self.encroot + '/' + encpath)
            except: pass
            del dir.children[path]
            dir.st_mtime = prev_mtime
            raise
        self.fd += 1
        return self.fd

    def flush(self, path, fh):
        if not self.write_dirty:
            log.debug('nothing to flush')
            return 0
        ent = self._find(self.write_path)
        encpath = self.encroot + '/' + ent.path
        buf = ''.join(self.write_buf)
        self.write_buf = [buf]
        encrypt(self.gpg, self.keyid, encpath+'.new', buf)
        prev_size = ent.st_size
        ent.st_size = len(buf)
        try:
            self._write_index(suffix='.new')
        except:
            os.remove(encpath+'.new')
            ent.st_size = prev_size
            raise
        # FIXME renames cannot fail, right?
        os.rename(encpath+'.new', encpath)
        os.rename(self.index_path+'.new', self.index_path)
        self.write_dirty = False
        log.debug('flushed %d bytes to %s', len(buf), self.write_path)
        return 0

    def getattr(self, path, fh = None):
        ent = self._find(path)
        if ent.type == ENT_DIR:
            return dict(st_mode = stat.S_IFDIR | ent.st_mode,
                        st_size = len(ent.children),
                        st_ctime = ent.st_ctime, st_mtime = ent.st_mtime,
                        st_atime = 0, st_nlink = 3)
        # ensure st_size is up-to-date
        self.flush(path, 0)
        encpath = self.encroot + '/' + ent.path
        s = os.stat(encpath)
        return dict(st_mode = s.st_mode, st_size = ent.st_size,
                    st_atime = s.st_atime, st_mtime = s.st_mtime,
                    st_ctime = s.st_ctime, st_nlink = s.st_nlink)

    def getxattr(self, path, name, position = 0):
        raise FuseOSError(errno.ENODATA) # ENOATTR

    def listxattr(self, path):
        return []

    def mkdir(self, path, mode):
        dir, path = self._find(path, parent=True)
        if path in dir.children:
            raise FuseOSError(errno.EEXIST)
        prev_mtime = dir.st_mtime
        dir.children[path] = Entry(type=ENT_DIR, children={},
                                   st_mode=(mode & 0777),
                                   st_mtime=int(time.time()),
                                   st_ctime=int(time.time()))
        dir.st_mtime = int(time.time())
        try:
            self._write_index()
        except:
            del dir.children[path]
            dir.st_mtime = prev_mtime
            raise

    def open(self, path, flags):
        return 0

    def read(self, path, size, offset, fh):
        self.flush(path, 0)
        ent = self._find(path)
        assert ent.type == ENT_FILE
        encpath = self.encroot + '/' + ent.path
        data = decrypt(self.gpg, encpath)
        return data[offset:offset + size]

    def readdir(self, path, fh):
        dir = self._find(path)
        return ['.', '..'] + list(dir.children)

    def readlink(self, path):
        raise FuseOSError(errno.ENOSYS)

    def removexattr(self, path, name):
        raise FuseOSError(errno.ENOSYS)

    def rename(self, old, new):
        self.flush(old, 0)
        self._clear_write_cache()
        if new.startswith(old):
            raise FuseOSError(errno.EINVAL)
        old_dir, old_name = self._find(old, parent=True)
        if old_name not in old_dir.children:
            raise FuseOSError(errno.ENOENT)
        new_dir, new_name = self._find(new, parent=True)
        prev_ent = new_dir.children.get(new_name)
        if prev_ent:
            if prev_ent.type == ENT_DIR:
                if old_dir[old_name].type != ENT_DIR:
                    raise FuseOSError(errno.EISDIR)
                if prev_ent.children:
                    raise FuseOSError(errno.ENOTEMPTY)
            elif old_dir[old_name].type == ENT_DIR:
                raise FuseOSError(errno.ENOTDIR)
        prev_old_mtime = old_dir.st_mtime
        prev_new_mtime = new_dir.st_mtime
        new_dir.children[new_name] = old_dir.children.pop(old_name)
        old_dir.st_mtime = new_dir.st_mtime = int(time.time())
        try:
            self._write_index()
        except:
            old_dir.children[old_name] = new_dir.children.pop(new_name)
            if prev_ent:
                new_dir.children[new_name] = prev_ent
            old_dir.st_mtime = prev_old_mtime
            new_dir.st_mtime = prev_new_mtime
            raise
        if prev_ent and prev_ent.type == ENT_FILE:
            os.remove(self.encroot + '/' + prev_ent.path)

    def rmdir(self, path):
        parent, path = self._find(path, parent=True)
        if path not in parent.children:
            raise FuseOSError(errno.ENOENT)
        ent = parent.children[path]
        if ent.type != ENT_DIR:
            raise FuseOSError(errno.ENOTDIR)
        if ent.children:
            raise FuseOSError(errno.ENOTEMPTY)
        prev_mtime = parent.st_mtime
        del parent.children[path]
        parent.st_mtime = int(time.time())
        try:
            self._write_index()
        except:
            parent.children[path] = ent
            parent.st_mtime = prev_mtime
            raise

    def setxattr(self, path, name, value, options, position = 0):
        raise FuseOSError(errno.ENOSYS)

    def statfs(self, path):
        raise FuseOSError(errno.ENOSYS)

    def symlink(self, target, source):
        raise FuseOSError(errno.ENOSYS)

    def truncate(self, path, length, fh = None):
        self.flush(path, 0)
        self._clear_write_cache()
        ent = self._find(path)
        encpath = self.encroot + '/' + ent.path
        if length == 0:
            with open(encpath+'.new', 'w'):
                pass
        else:
            buf = decrypt(self.gpg, encpath)
            buf = buf[:length]
            encrypt(self.gpg, self.keyid, encpath+'.new', buf)
        prev_size = ent.st_size
        ent.st_size = length
        try:
            self._write_index(suffix='.new')
        except:
            ent.st_size = prev_size
            os.remove(encpath+'.new')
            raise
        # FIXME renames cannot fail, right?
        os.rename(encpath+'.new', encpath)
        os.rename(self.index_path+'.new', self.index_path)

    def unlink(self, path):
        if self.write_path == path:
            # no need to flush afterwards
            self._clear_write_cache()
        dir, name = self._find(path, parent=True)
        if name not in dir.children:
            raise FuseOSError(errno.ENOENT)
        ent = dir.children[name]
        encpath = self.encroot + '/' + ent.path
        del dir.children[name]
        prev_mtime = dir.st_mtime
        dir.st_mtime = int(time.time())
        try:
            self._write_index()
        except:
            dir.children[name] = ent
            dir.st_mtime = prev_mtime
            raise
        os.remove(encpath)

    def utimens(self, path, times = None):
        ent = self._find(path)
        if ent.type == ENT_DIR:
            prev_mtime = ent.st_mtime
            if times is None:
                ent.st_mtime = int(time.time())
            else:
                ent.st_mtime = times[1]
            try:
                self._write_index()
            except:
                ent.st_mtime = prev_mtime
                raise
        else:
            # flush may mess with mtime
            self.flush(path, 0)
            encpath = self.encroot + '/' + ent.path
            os.utime(encpath, times)

    def write(self, path, data, offset, fh):
        ent = self._find(path)
        encpath = self.encroot + '/' + ent.path
        if path != self.write_path:
            self.flush(self.write_path, None)
            buf = decrypt(self.gpg, encpath)
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
    fs = GpgFs(sys.argv[2], sys.argv[1])
    FUSE(fs, sys.argv[3], foreground=True)
