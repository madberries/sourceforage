import itertools
import re
import shutil

from tempfile import mkstemp

def sed0(fin, fout, pattern, replace, count):
    num_replaced = count
    success = False

    for line in fin:
        out = re.sub(pattern, replace, line)
        fout.write(out)

        if out != line:
            success = True
            num_replaced += 1
        if count and num_replaced > count:
            break

    try:
        fout.writelines(fin.readlines())
    except Exception as E:
        raise E

    return success

def sed(pattern, replace, source, dest=None, count=0):
    """Reads a source file and writes the destination file.

    In each line, replaces pattern with replace.

    Args:
        pattern (str): pattern to match (can be re.pattern)
        replace (str): replacement str
        source  (str): input filename
        count (int): number of occurrences to replace
        dest (str): destination filename, if not given, source will
                    be over written.
    """

    success = False
    with open(source, 'r') as fin:
        if dest:
            with open(dest, 'w') as fout:
                success = sed0(fin, fout, pattern, replace, count)
        else:
            fd, name = mkstemp()
            with open(name, 'w') as fout:
                success = sed0(fin, fout, pattern, replace, count)

    if not dest:
        shutil.move(name, source)

    return success

def make_replacements(replacement_list, config_file):
    for varname, value in itertools.product(*replacement_list):
        if sed(r'(^\$' + varname + '\s*=\s*("|\'))[^"]+(("|\')\s*;.*$)',
                r'\1' + value + r'\3', config_file, count=1):
            break

def strip_ansi_color(data):
    """Remove ANSI colors from string or bytes."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")

    # Taken from tabulate
    invisible_codes = re.compile(r"\x1b\[\d*m")

    return re.sub(invisible_codes, "", data)

def border(s):
    x = '*' * (len(s)+4)
    return '%s\n* %s *\n%s' % (x, s, x)
