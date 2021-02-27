import os

from .constants import SUPPORTED_EXTS
from .zip import UnsupportedArchive

def without_ext(filename):
    for ext in SUPPORTED_EXTS:
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

def root_of_relpath(relpath):
    if relpath.startswith('.') or relpath.startswith(os.path.sep):
        raise ValueError
    last = relpath
    while relpath != '':
        last = relpath
        relpath = os.path.dirname(relpath)
    return last

def read_all_lines(filename):
    with open(filename) as f:
        return ''.join(f.readlines())

def replace_lines(filename, line_nos, to_replace):
    if len(line_nos) != len(to_replace):
        raise ValueError
    # Make sure that the line numbers are sorted (and to_replace should be
    # permuted with that same ordering)
    line_nos, to_replace = zip(*sorted(zip(line_nos, to_replace)))
    with open(filename, 'r+') as f:
        # Read in the lines of the file into a list, and then replace only the
        # lines corresponding to line_nos/to_replace.
        lines = f.readlines()
        for i in range(0, len(line_nos)):
            lines[line_nos[i] - 1] = to_replace[i] + '\n'

        # Go back to the beginning of the file, and now write the new lines of
        # the file.
        f.seek(0)
        for line in lines:
            print(line, file=f, end="")
        f.truncate()  # Correct the file length, since it may be smaller than
                      # the original
