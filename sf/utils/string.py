import itertools
import math
import os
import re
import shutil
import textwrap

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


def make_replacements(replacement_list, config_file, log):
    for varname, value_to_replace in itertools.product(*replacement_list):
        # If it's a a tuple, the the first element is the value to replace,
        # and the second element is the value to match.
        if type(value_to_replace) is tuple:
            value_to_replace, value_to_match = value_to_replace
            single_qmatch = double_qmatch = value_to_match
        else:
            single_qmatch = r"[^']*"
            double_qmatch = r'[^"]*'
        pattern = rf'^\$({varname})\s*=\s*(\'({single_qmatch})\'|"({double_qmatch})"(.*$))'
        ngroups = re.compile(pattern).groups
        replace = rf'$\1 = "{value_to_replace}"\{ngroups}'
        log.debug(
            f"Attempting to match '{pattern}' and replace with '{replace}'..."
        )
        if sed(pattern, replace, config_file, count=1):
            log.debug(
                f"Successfully replaced variable ${varname} with the value "
                f"\"{value_to_replace}\""
            )
            return True
    return False


def screen_width():
    _, cols = os.popen('stty size', 'r').read().split()
    return int(cols)


def pad_with_spaces(msg, cols=None, right_justify=False):
    if cols is None:
        cols = screen_width()
    if right_justify:
        fmt = "{:>%d}"
    else:
        fmt = "{:<%d}"
    return (fmt % (cols - 1)).format(msg)


def border(s):
    b = '*' * (len(s) + 4)
    return f"{b}\n* {s} *\n{b}"


def pretty_print_dir_contents(dirlisting, print_func=print):
    folders, files = dirlisting
    folders = [x for x in folders.keys()]
    files = [x for x in files.keys()]
    if len(files) + len(folders) <= 0:
        print_func('    <empty>')
    else:
        folders.sort()
        files.sort()
        for d in folders:
            print_func(f"    + {d}")
        for f in files:
            print_func(f"    - {f}")


def wrap_text(s, width=None, indent_on_newline=0):
    if indent_on_newline < 0:
        raise ValueError
    if width is None:
        width = screen_width()
    wrapped = textwrap.wrap(s, width=width)
    if indent_on_newline == 0:
        return '\n'.join(wrapped)
    first_line = wrapped[0]
    remaining_lines = '\n'.join(wrapped[1:])
    reduced_width = width - indent_on_newline
    margin = ' ' * indent_on_newline
    remaining_lines = textwrap.wrap(remaining_lines, width=reduced_width)
    remaining_lines = '\n'.join([margin + x for x in remaining_lines])
    return f"{first_line}\n{remaining_lines}"


def contains_substr(s, substr, ignore_case=True):
    try:
        if ignore_case:
            return s.lower().index(substr.lower())
        else:
            return s.index(substr)
    except ValueError:
        return -1


def make_title(msg, width=80, pad='-'):
    msg_len = len(msg)
    num_pad_chars = width - msg_len - 2    # The 2 accounts for extra spaces
    half_of_num_pad_chars = num_pad_chars / 2
    left_pad = pad * math.floor(half_of_num_pad_chars)
    right_pad = pad * math.ceil(half_of_num_pad_chars)
    return f"{left_pad} {msg} {right_pad}"
