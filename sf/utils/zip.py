import tarfile

from io import BytesIO
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
    else:
        if filename.endswith('.tar.gz') or filename.endswith('.tgz'):
            mode = 'r:gz'
        elif filename.endswith('.tar.bz2'):
            mode = 'r:bz2'
        else:
            raise UnsupportedArchive('File type not supported: ' + filename)

        with tarfile.open(fileobj=mem_zip, mode=mode) as tf:
            tf.extractall(extracted_path)
