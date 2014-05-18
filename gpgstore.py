
import os
import gnupg
from binascii import hexlify
import errno
import logging

log = logging.getLogger('gpgfs')

FMT_GPG = 0

class GpgStore(object):
    def __init__(self, encroot, keyid):
        self.encroot = encroot
        self.keyid = keyid
        self.gpg = gnupg.GPG()

    def put(self, data, path=None, format=FMT_GPG):
        assert format == FMT_GPG
        if not path:
            path = hexlify(os.urandom(20))
            path = path[:2] + '/' + path[2:]
            encdir = self.encroot + '/' + path[:2]
            if not os.path.exists(encdir):
                os.mkdir(encdir, 0755)
        res = self.gpg.encrypt(data, self.keyid, armor=False)
        if not res.ok:
            log.error("encryption failed (keyid %s), %s: %s",
                      self.keyid, res.status, path)
            raise OSError(errno.EIO)
        try:
            with file(self.encroot + '/' + path + '.tmp', 'w') as fd:
                fd.write(res.data)
            os.rename(self.encroot + '/' + path + '.tmp',
                      self.encroot + '/' + path)
        except IOError, err:
            log.error("write failed: %s: %s", path, str(err))
            raise OSError(err.errno)
        finally:
            try: os.remove(self.encroot + '/' + path + '.tmp')
            except: pass
        log.debug('encrypted %s' % path)
        return path

    def get(self, path, format=FMT_GPG):
        assert format == FMT_GPG
        try:
            data = file(self.encroot + '/' + path).read()
        except OSError, err:
            log.error("read failed: %s: %s", path, str(err))
            raise
        if not data:
            return data
        res = self.gpg.decrypt(data)
        if not res.ok:
            log.error("decryption failed, %s: %s", res.status, path)
            raise OSError(errno.EIO)
        log.debug('decrypted %s' % path)
        return data

    def delete(self, path):
        os.remove(self.encroot + '/' + path)
        log.debug('deleted %s' % path)

    def exists(self, path):
        return os.path.exists(self.encroot + '/' + path)
