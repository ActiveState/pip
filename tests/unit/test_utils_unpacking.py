import io
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import time
import zipfile

import pytest

from pip._internal.exceptions import InstallationError
from pip._internal.utils.unpacking import (
    is_within_directory,
    unpack_file,
    untar_file,
    unzip_file,
)


class TestUnpackArchives(object):
    """
    test_tar.tgz/test_tar.zip have content as follows engineered to confirm 3
    things:
     1) confirm that reg files, dirs, and symlinks get unpacked
     2) permissions are not preserved (and go by the 022 umask)
     3) reg files with *any* execute perms, get chmod +x

       file.txt         600 regular file
       symlink.txt      777 symlink to file.txt
       script_owner.sh  700 script where owner can execute
       script_group.sh  610 script where group can execute
       script_world.sh  601 script where world can execute
       dir              744 directory
       dir/dirfile      622 regular file
     4) the file contents are extracted correctly (though the content of
        each file isn't currently unique)

    """

    def setup(self):
        self.tempdir = tempfile.mkdtemp()
        self.old_mask = os.umask(0o022)
        self.symlink_expected_mode = None

    def teardown(self):
        os.umask(self.old_mask)
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def confirm_files(self):
        # expectations based on 022 umask set above and the unpack logic that
        # sets execute permissions, not preservation
        for fname, expected_mode, test, expected_contents in [
            ('file.txt', 0o644, os.path.isfile, b'file\n'),
            # We don't test the "symlink.txt" contents for now.
            ('symlink.txt', 0o644, os.path.isfile, None),
            ('script_owner.sh', 0o755, os.path.isfile, b'file\n'),
            ('script_group.sh', 0o755, os.path.isfile, b'file\n'),
            ('script_world.sh', 0o755, os.path.isfile, b'file\n'),
            ('dir', 0o755, os.path.isdir, None),
            (os.path.join('dir', 'dirfile'), 0o644, os.path.isfile, b''),
        ]:
            path = os.path.join(self.tempdir, fname)
            if path.endswith('symlink.txt') and sys.platform == 'win32':
                # no symlinks created on windows
                continue
            assert test(path), path
            if expected_contents is not None:
                with open(path, mode='rb') as f:
                    contents = f.read()
                assert contents == expected_contents, 'fname: {}'.format(fname)
            if sys.platform == 'win32':
                # the permissions tests below don't apply in windows
                # due to os.chmod being a noop
                continue
            mode = self.mode(path)
            assert mode == expected_mode, (
                "mode: {}, expected mode: {}".format(mode, expected_mode)
            )

    def make_zip_file(self, filename, file_list):
        """
        Create a zip file for test case
        """
        test_zip = os.path.join(self.tempdir, filename)
        with zipfile.ZipFile(test_zip, 'w') as myzip:
            for item in file_list:
                myzip.writestr(item, 'file content')
        return test_zip

    def make_tar_file(self, filename, file_list):
        """
        Create a tar file for test case
        """
        test_tar = os.path.join(self.tempdir, filename)
        with tarfile.open(test_tar, 'w') as mytar:
            for item in file_list:
                file_tarinfo = tarfile.TarInfo(item)
                mytar.addfile(file_tarinfo, 'file content')
        return test_tar

    def test_unpack_tgz(self, data):
        """
        Test unpacking a *.tgz, and setting execute permissions
        """
        test_file = data.packages.joinpath("test_tar.tgz")
        untar_file(test_file, self.tempdir)
        self.confirm_files()
        # Check the timestamp of an extracted file
        file_txt_path = os.path.join(self.tempdir, 'file.txt')
        mtime = time.gmtime(os.stat(file_txt_path).st_mtime)
        assert mtime[0:6] == (2013, 8, 16, 5, 13, 37), mtime

    def test_unpack_zip(self, data):
        """
        Test unpacking a *.zip, and setting execute permissions
        """
        test_file = data.packages.joinpath("test_zip.zip")
        unzip_file(test_file, self.tempdir)
        self.confirm_files()

    def test_unpack_zip_failure(self):
        """
        Test unpacking a *.zip with file containing .. path
        and expect exception
        """
        files = ['regular_file.txt', os.path.join('..', 'outside_file.txt')]
        test_zip = self.make_zip_file('test_zip.zip', files)
        with pytest.raises(InstallationError) as e:
            unzip_file(test_zip, self.tempdir)
        assert 'trying to install outside target directory' in str(e.value)

    def test_unpack_zip_success(self):
        """
        Test unpacking a *.zip with regular files,
        no file will be installed outside target directory after unpack
        so no exception raised
        """
        files = [
            'regular_file1.txt',
            os.path.join('dir', 'dir_file1.txt'),
            os.path.join('dir', '..', 'dir_file2.txt'),
        ]
        test_zip = self.make_zip_file('test_zip.zip', files)
        unzip_file(test_zip, self.tempdir)

    def test_unpack_tar_failure(self):
        """
        Test unpacking a *.tar with file containing .. path
        and expect exception
        """
        files = ['regular_file.txt', os.path.join('..', 'outside_file.txt')]
        test_tar = self.make_tar_file('test_tar.tar', files)
        with pytest.raises(InstallationError) as e:
            untar_file(test_tar, self.tempdir)
        assert 'trying to install outside target directory' in str(e.value)

    def test_unpack_tar_success(self):
        """
        Test unpacking a *.tar with regular files,
        no file will be installed outside target directory after unpack
        so no exception raised
        """
        files = [
            'regular_file1.txt',
            os.path.join('dir', 'dir_file1.txt'),
            os.path.join('dir', '..', 'dir_file2.txt'),
        ]
        test_tar = self.make_tar_file('test_tar.tar', files)
        untar_file(test_tar, self.tempdir)

    def test_unpack_tar_symlink_escape_failure(self):
        """
        CVE-2025-8869: a tar symlink whose target is not a member of the
        archive (i.e. points to an arbitrary host path) must be rejected.
        """
        test_tar = os.path.join(self.tempdir, 'evil_symlink.tar')
        with tarfile.open(test_tar, 'w') as tar:
            info = tarfile.TarInfo('evil_link')
            info.type = tarfile.SYMTYPE
            info.linkname = os.path.join('..', '..', '..', 'etc', 'passwd')
            tar.addfile(info)
        with pytest.raises(InstallationError) as e:
            untar_file(test_tar, os.path.join(self.tempdir, 'out'))
        assert 'trying to point outside target directory' in str(e.value)

    def test_unpack_tar_symlink_to_member_success(self):
        """
        A tar symlink pointing at another member of the same archive is safe
        and is extracted unchanged.
        """
        test_tar = os.path.join(self.tempdir, 'good_symlink.tar')
        content = b'data\n'
        with tarfile.open(test_tar, 'w') as tar:
            finfo = tarfile.TarInfo('target.txt')
            finfo.size = len(content)
            tar.addfile(finfo, io.BytesIO(content))
            linfo = tarfile.TarInfo('link.txt')
            linfo.type = tarfile.SYMTYPE
            linfo.linkname = 'target.txt'
            tar.addfile(linfo)
        out = os.path.join(self.tempdir, 'out')
        untar_file(test_tar, out)
        link_path = os.path.join(out, 'link.txt')
        assert os.path.islink(link_path)
        assert os.readlink(link_path) == 'target.txt'

    def test_unpack_tar_symlink_then_member(self):
        """Reject a symlink to outside before a member is written through it.

        CVE-2025-8869 follow-up (pypa/pip#14127). Python 2.7 has no
        ``tarfile.data_filter``, so this check is the only protection.
        """
        tar_filepath = os.path.join(self.tempdir, 'symlink_then_member.tar')
        extract_path = os.path.join(self.tempdir, 'extract_path')
        outside_path = os.path.join(self.tempdir, 'outside.txt')

        with tarfile.open(tar_filepath, 'w') as tar:
            info = tarfile.TarInfo('outside_link')
            info.type = tarfile.SYMTYPE
            info.linkname = '..'
            tar.addfile(info)

            data = b'data\n'
            info = tarfile.TarInfo('outside_link/outside.txt')
            info.size = len(data)
            tar.addfile(info, fileobj=io.BytesIO(data))

            info = tarfile.TarInfo('..')
            info.type = tarfile.DIRTYPE
            tar.addfile(info)

        with pytest.raises(InstallationError):
            untar_file(tar_filepath, extract_path)

        assert not os.path.exists(outside_path)
        assert not os.path.exists(os.path.join(extract_path, 'outside_link'))

    def test_unpack_tar_nested_symlink_traversal(self):
        """Reject a member that escapes through a chain of in-bounds symlinks.

        CVE-2025-8869 follow-up (pypa/pip#14127).
        """
        tar_filepath = os.path.join(self.tempdir, 'nested_traversal.tar')
        extract_path = os.path.join(self.tempdir, 'extract_path')
        outside_path = os.path.join(self.tempdir, 'outside.txt')

        with tarfile.open(tar_filepath, 'w') as tar:
            info = tarfile.TarInfo('.')
            info.type = tarfile.DIRTYPE
            tar.addfile(info)

            info = tarfile.TarInfo('redir')
            info.type = tarfile.SYMTYPE
            info.linkname = '.'
            tar.addfile(info)

            info = tarfile.TarInfo('redir/up')
            info.type = tarfile.SYMTYPE
            info.linkname = '..'
            tar.addfile(info)

            data = b'data\n'
            info = tarfile.TarInfo('redir/up/outside.txt')
            info.size = len(data)
            tar.addfile(info, fileobj=io.BytesIO(data))

        with pytest.raises(InstallationError):
            untar_file(tar_filepath, extract_path)

        assert not os.path.exists(outside_path)


@pytest.mark.parametrize('args, expected', [
    # Test the second containing the first.
    (('parent/sub', 'parent/'), False),
    # Test the first not ending in a trailing slash.
    (('parent', 'parent/foo'), True),
    # Test target containing `..` but still inside the parent.
    (('parent/', 'parent/foo/../bar'), True),
    # Test target within the parent
    (('parent/', 'parent/sub'), True),
    # Test target outside parent
    (('parent/', 'parent/../sub'), False),
    # CVE-2026-1703: a sibling whose name has the directory as a string
    # prefix must not be considered "within" it.
    (('parent/child', 'parent/childfoo'), False),
    # A filesystem root contains everything below it.
    (('/', '/usr/bin/pip'), True),
    (('/', '/'), True),
])
def test_is_within_directory(args, expected):
    result = is_within_directory(*args)
    assert result == expected


@pytest.mark.skipif("sys.platform == 'win32'")
def test_is_within_directory_doubled_slash_root():
    # POSIX keeps a leading "//"; the containment check must too.
    assert is_within_directory('//srv/env/bin', '//srv/env/bin/pip')
    assert not is_within_directory('//srv/env/bin', '//srv/env/binfoo')


def test_is_within_directory_resolve_symlinks(tmpdir):
    base = str(tmpdir)
    inside = os.path.join(base, 'inside')
    os.mkdir(inside)
    if not hasattr(os, 'symlink'):
        pytest.skip('os.symlink is unavailable')
    os.symlink(base, os.path.join(inside, 'up'))
    target = os.path.join(inside, 'up', 'outside.txt')
    # Textually inside, but the symlink resolves to the parent.
    assert is_within_directory(inside, target)
    assert not is_within_directory(inside, target, resolve_symlinks=True)


def _make_tar_zip_polyglot(path):
    """Write a valid .tar.gz with a valid ZIP appended (a polyglot file).

    The tar view and the zip view each contain a ``payload.txt`` with
    different contents so a test can tell which format pip chose.
    """
    # Use a top-level directory (as real sdists/wheels do) so pip's
    # leading-directory flattening behaves the same for both views.
    tar_buf = io.BytesIO()
    tar = tarfile.open(fileobj=tar_buf, mode='w:gz')
    data = b'from-tar'
    info = tarfile.TarInfo('pkg/payload.txt')
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))
    tar.close()

    zip_buf = io.BytesIO()
    zf = zipfile.ZipFile(zip_buf, 'w')
    zf.writestr('pkg/payload.txt', 'from-zip')
    zf.close()

    with open(path, 'wb') as fp:
        fp.write(tar_buf.getvalue() + zip_buf.getvalue())


@pytest.mark.parametrize('filename, content_type, expected', [
    # CVE-2026-3219: a .tar.gz polyglot must be treated as a tar (by its
    # name), not silently as the appended zip.
    ('pkg.tar.gz', None, b'from-tar'),
    ('pkg.tgz', None, b'from-tar'),
    ('pkg.zip', None, b'from-zip'),
    # An explicit content-type wins over the filename.
    ('pkg.tar.gz', 'application/zip', b'from-zip'),
    ('pkg.bin', 'application/x-gzip', b'from-tar'),
])
def test_unpack_polyglot_routing(tmpdir, filename, content_type, expected):
    archive = os.path.join(str(tmpdir), filename)
    _make_tar_zip_polyglot(archive)
    out = os.path.join(str(tmpdir), 'out')
    unpack_file(archive, out, content_type=content_type)
    with open(os.path.join(out, 'payload.txt'), 'rb') as fp:
        assert fp.read() == expected


def test_unpack_polyglot_ambiguous_rejected(tmpdir):
    """
    CVE-2026-3219: with no usable content-type or extension, a file that is
    both a valid zip and a valid tar is ambiguous and must be rejected.
    """
    archive = os.path.join(str(tmpdir), 'pkg.unknownext')
    _make_tar_zip_polyglot(archive)
    with pytest.raises(InstallationError):
        unpack_file(archive, os.path.join(str(tmpdir), 'out'))
