import configparser
import os
import shutil
import sys

from pathlib import Path

from .utils.file import replace_lines
from .utils.logging import ItemizedLogger


def dockerize(root_dir, path_to_codebase, log, use_old_template=False):
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

        # Extract the configuration variables needed for dockerization.
        cve = cve_section['id']
        cpe = cve_section['cpe']
        version = cve_section['version']
        vuln_file = cve_section['vuln_file']

        # Make sure the vulnerable file is where we are expecting it to be.
        if not Path(vuln_file).exists():
            log.error(
                f"ERROR: Vulnerable file '{vuln_file_path}' does not "
                'exist!'
            )
            return False

        # Determine which template we should dockerize from.
        if use_old_template:
            template_suffix = 'old'
        else:
            template_suffix = 'new'
        template_dir = '../../templates/baseline_' + template_suffix

        # Make sure the template directory can be located.
        if not Path(template_dir).is_dir():
            log.error(
                f"ERROR: Template directory '{template_dir}' either "
                'does not exist, or is not a directory!'
            )
            return False

        # Make sure that the directory for the CVE we will dockerize does not
        # already exist.
        cve_dir = cve.lower()
        if Path(cve_dir).exists():
            log.error(f"ERROR: CVE directory '{cve_dir}' already exists!")
            return False

        data_dir = os.path.join(cve_dir, 'data')
        working_codebase = os.path.join(data_dir, path_to_codebase)

        # Copy the template zygote into the CVE directory for which we will
        # dockerize.  Also, copy over the codebase into the <CVE>/data/
        # directory.
        log.info(
            f"Copying {template_suffix} template from '{template_dir}' "
            f"to '{cve_dir}'"
        )
        shutil.copytree(template_dir, cve_dir, symlinks=True)
        log.info(
            f"Copying codebase '{path_to_codebase}' into "
            f"'{working_codebase}'"
        )
        shutil.copytree(path_to_codebase, working_codebase, symlinks=True)

        # Copy over the cve.ini file.
        shutil.copyfile('.cve.ini', os.path.join(cve_dir, '.cve.ini'))

        # Replace all of the relevant lines in the template to be consistent
        # with what's in the CVE ini file.
        replace_lines(
            os.path.join(cve_dir, 'README.md'), [1, 3],
            ['# %s' % cve, 'PHP exploit for %s (%s)' % (cve, vuln_file)]
        )
        replace_lines(
            os.path.join(cve_dir, 'config.yml'), [4, 16, 26],
            [
                'firmware_version: ' + version,
                'exploit_name: ' + cve,
                'cpe_product: ' + cpe
            ]
        )
        doit_path = os.path.join(cve_dir, os.path.join('data', 'doit.sh'))
        replace_lines(
            doit_path, [9, 10],
            [
                'docker build -t aarno-%s . || exit_on_error "Couldn\'t build '
                'docker container"' % cve_dir,
                'docker run --rm --privileged -p 80:80 aarno-%s' % cve_dir
            ]
        )
        docker_line = 'COPY ' + os.path.basename(path_to_codebase)
        if use_old_template:
            docker_line += '/ /var/www/html'
        else:
            docker_line += '/ /app'
        dockerfile = os.path.join(cve_dir, os.path.join('data', 'Dockerfile'))
        replace_lines(dockerfile, [3], [docker_line])
    finally:
        # Set the CWD back to it's original path.
        log.debug(f"Resetting CWD back to '{old_cwd}'")
        os.chdir(old_cwd)

    # Success!
    return True
