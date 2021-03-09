import os
import tarfile
import tempfile

from io import BytesIO
from unrar import rarfile
from zipfile import ZipFile

from .constants import SUPPORTED_EXTS


class UnsupportedArchive(Exception):
    pass


def is_supported_archive_type(filename):
    for ext in SUPPORTED_EXTS:
        if filename.endswith(ext):
            return True
    return False


def list_archive_contents(filename, contents):
    mem_zip = BytesIO(contents)
    if filename.endswith('.zip'):
        with ZipFile(mem_zip, mode="r") as zf:
            return zf.namelist()
    elif filename.endswith('.rar'):
        # Unfortunately need to write to temporary file for this library...
        tmp_file, tmp_filename = tempfile.mkstemp()
        os.write(tmp_file, mem_zip.read())
        os.close(tmp_file)

        with rarfile.RarFile(tmp_filename) as rar:
            filelist = [ x.filename for x in rar.filelist]

        # Remove the temporary RAR file that was created, and return the
        # archive listing.
        os.unlink(tmp_filename)
        return filelist
    else:
        if filename.endswith('.tar.gz') or filename.endswith('.tgz'):
            mode = 'r:gz'
        elif filename.endswith('.tar.bz2'):
            mode = 'r:bz2'
        else:
            raise UnsupportedArchive('File type not supported: ' + filename)

        names = []
        with tarfile.open(fileobj=mem_zip, mode=mode) as tf:
            for member in tf.getmembers():
                names.append(member.name)
        return names


def extract_archive(filename, contents, extracted_path):
    mem_zip = BytesIO(contents)
    if filename.endswith('.zip'):
        with ZipFile(mem_zip, mode="r") as zf:
            zf.extractall(extracted_path)
    elif filename.endswith('.rar'):
        # Unfortunately need to write to temporary file for this library...
        tmp_file, tmp_filename = tempfile.mkstemp()
        os.write(tmp_file, mem_zip.read())
        os.close(tmp_file)

        with rarfile.RarFile(tmp_filename) as rar:
            rar.extractall(path=extracted_path)

        # Remove the temporary RAR file that was created.
        os.unlink(tmp_filename)
    else:
        if filename.endswith('.tar.gz') or filename.endswith('.tgz'):
            mode = 'r:gz'
        elif filename.endswith('.tar.bz2'):
            mode = 'r:bz2'
        else:
            raise UnsupportedArchive('File type not supported: ' + filename)

        with tarfile.open(fileobj=mem_zip, mode=mode) as tf:
            tf.extractall(extracted_path)
