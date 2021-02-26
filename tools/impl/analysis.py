import configparser
import json
import os
import shutil

from pathlib import Path
from subprocess import Popen, PIPE

from .helpers.constants import GAAPHP_TIMEOUT, HACCSCMD_ROOT_DIR
from .helpers.file_utils import root_of_relpath
from .helpers.process_utils import run_cmd

def run_gaaphp(root_dir, cve_dir, additional_args=[]):
    old_cwd = os.getcwd()
    try:
        # To make things a bit easier let's chdir to root_dir, and we'll reset
        # this back later in the finally.
        print('Setting CWD to "%s"' % root_dir)
        os.chdir(root_dir)

        # Read in the CVE ini file.
        config = configparser.ConfigParser()
        config.read('.cve.ini')
        cve_section = config['cve']
        analysis_section = config['analysis']

        # Extract the configuration variables needed for analysis.
        vuln_file = cve_section['vuln_file']
        reg_globals = analysis_section.getboolean('register_globals',
                                                  fallback=False)
        sqlarity = analysis_section.getboolean('sqlarity', fallback=False)
        sqlarity_str = analysis_section.get('sqlarity_string')
        sqlarity_hack = analysis_section.get('sqlarity_hack')
        path_prefix = analysis_section.get('path_prefix')
        seed = analysis_section.getint('seed')
        skip = analysis_section.getboolean('skip', fallback=False)
        if skip:
            print('Skipping analysis for "%s"' % cve_dir)
            return False

        # Make sure the CVE directory containing the codebase that we will be
        # analyzing exists.
        if not Path(cve_dir).is_dir():
            print('ERROR: CVE directory "%s" either does not exist or is not a '
                  'directory!' % cve_dir, file=sys.stderr)
            return False

        data_dir = os.path.join(cve_dir, 'data')
        codebase_dir = root_of_relpath(vuln_file)

        # TODO: remove hardcoded path!
        gaaphp_dir = os.path.join('/home/jeikenberry',
                                  'haccs/gaaphp/StrangerTool')
        output_json = os.path.join(gaaphp_dir, 'output-egen.json')
        output_txt  = os.path.join(gaaphp_dir, 'output-egen.txt')

        # Remove old analysis (just to be sure gaaphp actually writes this even
        # on erroneous executions).
        if os.path.exists(output_json):
            os.remove(output_json)
        if os.path.exists(output_txt):
            os.remove(output_txt)

        # Concatenate all of the command-line arguments to gaaphp.
        # TODO: call this directly without making an exec() syscall
        cmd = [ 'python3', 'extract-attacks.py', '--via-php',
                os.path.abspath(vuln_file), '--egen', '--analysis=sql' ]
        if seed is not None:
            cmd += [ '--seed=%d' % seed ]
        if path_prefix is not None:
            cmd += [ '--pathprefix=%s' % path_prefix ]
        if reg_globals:
            cmd += [ "--newtool-flags='--register_globals'" ]
        if sqlarity:
            if sqlarity_str is not None:
                cmd += [ '--sqlarity', sqlarity_str ]
            else:
                sqlarity_str = os.path.abspath(codebase_dir)
                if sqlarity_hack:
                    sqlarity_str += '/hack'
                out, _ = Popen(['python3', gaaphp_dir + '/sqlarity.py',
                    sqlarity_str], stdout=PIPE).communicate()
                out = out.splitlines()
                if len(out) != 1:
                    print('ERROR: Unexpected size of output '
                          '(num_of_lines = %d) != 1!' % len(out),
                          file=sys.stderr)
                    print('OUTPUT:', file=sys.stderr)
                    for line in out:
                        print('    ' + line.decode('utf-8'), file=sys.stderr)
                    return False
                cmd += [ '--sqlarity', out[0].decode('utf-8') ]

        # Run the analysis via gaaphp.
        if not run_cmd(cmd, 'gaaphp analysis', timeout=GAAPHP_TIMEOUT,
                       cwd=gaaphp_dir):
            return False

        if not Path(output_json).is_file():
            print('ERROR: No JSON output was generated!', file=sys.stderr)

        all_json_lines = ''
        with open(output_json) as f:
            lines = f.readlines()
            if len(lines) < 1:
                print('ERROR: JSON output returned is empty!', file=sys.stderr)
                return False
            elif len(lines) == 1 and lines[0] == '[]':
                print('ERROR: No vulnerability detected in JSON output!',
                      file=sys.stderr)
                return false
            for line in lines:
                all_json_lines += line

        # Dump out the JSON vulnerability.
        print('Vulnerability sucessfully detected:')
        parsed_json = json.loads(all_json_lines)
        print(json.dumps(parsed_json, indent=4))

        # Copy over the analysis results to the JSON directory in comfortfuzz
        # for comfortfuzz to generate an exploit from this.
        copy_to_dir = os.path.join(HACCSCMD_ROOT_DIR, 'comfortfuzz/json_out')
        shutil.copyfile(output_json, os.path.join(copy_to_dir,
                        'egen-%s.json' % cve_dir))

    finally:
        # Set the CWD back to it's original path.
        print('Resetting CWD back to "%s"' % old_cwd)
        os.chdir(old_cwd)

    # Success!
    return True
