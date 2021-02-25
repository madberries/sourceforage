import os

from .zip_utils import UnsupportedArchive, supported_exts

def without_ext(filename):
    for ext in supported_exts:
        try:
            idx = filename.rindex(ext)
            return filename[:idx]
        except ValueError:
            pass
    raise UnsupportedArchive('File type not supported: ' + filename)

def get_filename_from_download_url(download_url):
    url_split = download_url.split('/')
    assert(url_split[len(url_split)-1] == 'download'), \
            'Unexpected url format: ' + download_url
    return url_split[len(url_split)-2]

def leaf_of_path(path):
    if path.endswith(os.path.sep):
        return os.path.basename(path[:-1])
    return os.path.basename(path)

