from .zip_utils import UnsupportedArchive, supported_exts

def without_ext(filename):
    for ext in supported_exts:
        try:
            idx = filename.rindex(ext)
            return filename[:idx]
        except ValueError:
            pass
    raise UnsupportedArchive('File type not supported: ' + filename)
