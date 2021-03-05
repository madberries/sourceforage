import configparser
import json
import os
import shutil

from pathlib import Path
from subprocess import Popen, PIPE

from .utils.constants import GAAPHP_TIMEOUT, SF_ROOT_DIR
from .utils.file import root_of_relpath
from .utils.process import run_cmd
from .utils.string import make_title


def run_gaaphp(root_dir, cve_dir, log, additional_args=[]):
    old_cwd = os.getcwd()
    try:
        # To make things a bit easier let's chdir to root_dir, and we'll reset
        # this back later in the finally.
        log.debug(f"Setting CWD to '{root_dir}'")
        os.chdir(root_dir)

        # Read in the CVE ini file.
        config = configparser.ConfigParser()
        config.read('.cve.ini')
        cve_section = config['cve']
        analysis_section = config['analysis']

        # Extract the configuration variables needed for analysis.
        vuln_file = cve_section['vuln_file']
        reg_globals = analysis_section.getboolean(
            'register_globals', fallback=False
        )
        sqlarity = analysis_section.getboolean('sqlarity', fallback=False)
        sqlarity_str = analysis_section.get('sqlarity_string')
        sqlarity_hack = analysis_section.get('sqlarity_hack')
        path_prefix = analysis_section.get('path_prefix')
        seed = analysis_section.getint('seed')
        skip = analysis_section.getboolean('skip', fallback=False)
        if skip:
            log.warn(f"Skipping analysis for '{cve_dir}'")
            return False

        # Make sure the CVE directory containing the codebase that we will be
        # analyzing exists.
        if not Path(cve_dir).is_dir():
            log.error(
                f"CVE directory '{cve_dir}' either does not exist or is not a "
                'directory!'
            )
            return False

        data_dir = os.path.join(cve_dir, 'data')
        codebase_dir = root_of_relpath(vuln_file)

        # TODO: remove hardcoded path!
        gaaphp_dir = os.path.join(
            '/home/jeikenberry', 'haccs/gaaphp/StrangerTool'
        )
        output_json = os.path.join(gaaphp_dir, 'output-egen.json')
        output_txt = os.path.join(gaaphp_dir, 'output-egen.txt')

        # Remove old analysis (just to be sure gaaphp actually writes this even
        # on erroneous executions).
        if os.path.exists(output_json):
            os.remove(output_json)
        if os.path.exists(output_txt):
            os.remove(output_txt)

        # Concatenate all of the command-line arguments to gaaphp.
        # TODO: call this directly without making an exec() syscall.
        cmd = [
            'python3',
            'extract-attacks.py',
            '--via-php',
            os.path.abspath(vuln_file),
            '--egen',
            '--analysis=sql'
        ]
        if seed is not None:
            cmd += ['--seed=%d' % seed]
        if path_prefix is not None:
            cmd += ['--pathprefix=%s' % path_prefix]
        if reg_globals:
            cmd += ["--newtool-flags='--register_globals'"]
        if sqlarity:
            if sqlarity_str is not None:
                cmd += ['--sqlarity', sqlarity_str]
            else:
                sqlarity_str = os.path.abspath(codebase_dir)
                if sqlarity_hack:
                    sqlarity_str += '/hack'
                log.info(f"Running sqlarity on string '{sqlarity_str}'")
                out, _ = Popen(['python3', gaaphp_dir + '/sqlarity.py',
                    sqlarity_str], stdout=PIPE).communicate()
                out = out.splitlines()
                nlines = len(out)
                if nlines != 1:
                    log.error(
                        f"Unexpected size of output (#_of_lines={nlines}) != 1!"
                    )
                    log.debug(make_title('start of sqlarity.py output'))
                    for line in out:
                        log.debug('    ' + line.decode('utf-8'))
                    log.debug(make_title('end of sqlarity.py output'))
                    return False
                cmd += ['--sqlarity', out[0].decode('utf-8')]

        # Run the analysis via gaaphp.
        if not run_cmd(
            cmd, 'gaaphp analysis', log, timeout=GAAPHP_TIMEOUT, cwd=gaaphp_dir
        ):
            return False

        if not Path(output_json).is_file():
            log.error('No JSON output file was generated!')
            return False

        all_json_lines = ''
        with open(output_json) as f:
            lines = f.readlines()
            if len(lines) == 0:
                log.error('JSON output file is empty!')
                return False
            for line in lines:
                all_json_lines += line

        # Make sure there actually is a vulnerability in the JSON output.
        if all_json_lines.strip() == '[]':
            log.error('No vulnerability detected in JSON output!')
            return False

        # Dump out the JSON vulnerability.
        log.debug('Vulnerability sucessfully detected:')
        parsed_json = json.loads(all_json_lines)
        log.debug(json.dumps(parsed_json, indent=4))

        # Copy over the analysis results to the dockerized CVE directory.
        copy_to_file = os.path.join(cve_dir, 'output-egen.json')
        shutil.copyfile(output_json, copy_to_file)
    finally:
        # Set the CWD back to it's original path.
        log.debug(f"Resetting CWD back to '{old_cwd}'")
        os.chdir(old_cwd)

    # Success!
    return True
