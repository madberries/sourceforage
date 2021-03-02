import os
import itertools
import re
import requests
import selectors
import shutil
import sys
import traceback
import urllib.parse

from bs4 import BeautifulSoup
from datetime import datetime
from fuzzywuzzy import fuzz
from packaging import version
from packaging.version import LegacyVersion
from urllib.parse import urljoin

from .analysis import run_gaaphp
from .dockerizer import dockerize
from .exploit_runner import run_exploit
from .versions import VersionCondition, InvalidVersionFormat, \
                      compute_version_range
from .utils.constants import CAPABLE_OF_WORKING, FORAGED_OUT_DIR, \
                             SF_ROOT_DIR, SOURCEFORGE_BASE_URL
from .utils.file import get_filename_from_download_url, without_ext
from .utils.logging import ItemizedLogger, StepFailedException
from .utils.process import run_cmd
from .utils.string import border, contains_substr, pretty_print_dir_contents
from .utils.zip import extract_archive, is_supported_archive_type, \
                       list_archive_contents


class SourceforgeScraper:

    def __init__(
        self,
        cve,
        log,
        check_only_verified=False,
        success_msg='Exploit succeeded!'
    ):
        self.cve = cve
        self.log = log
        self.check_only_verified = check_only_verified
        self.success_msg = success_msg
        self.vuln_files = set()
        for word in cve.description.split(' '):
            if word.endswith('.php'):
                self.vuln_files.add(word)
        self.valid_version_ranges = []
        self.cpe_map = dict()
        self.cur_idx = 1

    def uniq_cve_dirname(self):
        cve_lower = self.cve.cve.lower()
        cur_dirname = cve_lower + '_%04d' % self.cur_idx
        self.cur_idx = self.cur_idx + 1
        return cur_dirname

    def generate_ini_file(self, cve_dir, cpe, vuln_file, **kwargs):
        cpe_split = cpe.split(':')
        with open(os.path.join(cve_dir, '.cve.ini'), 'w') as cve_ini_file:
            version = cpe_split[5]
            reg_globals = str(kwargs['reg_globals'])
            sqlarity = str(kwargs['sqlarity'])
            print('[cve]\n'               \
                  'id=%s\n'               \
                  'cpe=%s\n'              \
                  'version=%s\n'          \
                  'vuln_file=%s\n'        \
                  '\n'                    \
                  '[analysis]\n'          \
                  'register_globals=%s\n' \
                  'sqlarity=%s' % (self.cve.cve, cpe, version, vuln_file,
                      reg_globals, sqlarity), file=cve_ini_file)

    @staticmethod
    def search_for_name0(desc, name):
        search_idx = contains_substr(desc, name)
        if search_idx >= 0:
            return desc[search_idx:search_idx + len(name)]
        for replace in [' ', '-']:
            search_idx = contains_substr(desc, name.replace('_', replace))
            if search_idx >= 0:
                return desc[search_idx:search_idx + len(name)]
        return None

    @staticmethod
    def search_for_name(desc, first, second):
        if first != second:
            result = SourceforgeScraper.search_for_name0(
                desc, first + ' ' + second
            )
            if result is None:
                result = SourceforgeScraper.search_for_name0(desc, second)
            if result is None:
                result = SourceforgeScraper.search_for_name0(desc, first)
            return result
        else:
            return SourceforgeScraper.search_for_name0(desc, first)

    @staticmethod
    def find_codebase(project_name):
        results_map = dict()
        project_name = urllib.parse.quote(project_name)
        page = requests.get(
            f"{SOURCEFORGE_BASE_URL}/directory/language:php"
            f"/?q={project_name}"
        )
        contents = page.content
        soup = BeautifulSoup(contents, 'html.parser')
        projects = soup.find_all('a', { 'class': 'result-heading-title'})
        for project in projects:
            link = project.get('href')
            name = project.contents[1].string
            results_map[name] = link
        return results_map

    @staticmethod
    def get_codebase_file_listing(rel_path):
        _, files = \
                SourceforgeScraper.get_codebase_listing(rel_path,
                                                        listing_type="file")
        return files

    @staticmethod
    def get_codebase_dir_listing(rel_path):
        folders, _ = \
                SourceforgeScraper.get_codebase_listing(rel_path,
                                                        listing_type='folder')
        return folders

    @staticmethod
    def get_codebase_listing(rel_path, listing_type='file/folder'):
        folders_map = dict()
        files_map = dict()

        if not rel_path.endswith(os.path.sep):
            rel_path = rel_path + os.path.sep
        if not rel_path.startswith(os.path.sep):
            rel_path = os.path.sep + rel_path

        url = urljoin(SOURCEFORGE_BASE_URL, rel_path)
        page = requests.get(url)
        contents = page.content
        soup = BeautifulSoup(contents, 'html.parser')

        # Construct a listing of all file/folder -> url mappings found
        # on this page.
        for entity_type, entity_map in \
                [('folder', folders_map), ('file', files_map)]:
            entities = soup.find_all('tr', { 'class': entity_type })
            for entity in entities:
                title = entity.get('title')
                if title is not None:
                    entity_map[title] = entity.th.a.get('href')

        return folders_map, files_map

    def download_codebase(self, url, cpe, is_file):
        # If the url provided was from a file listing, then the URL provided
        # should already be the download URL
        if is_file:
            items = [('N/A', url)]
        else:
            items = SourceforgeScraper.get_codebase_file_listing(url).items()

        # Iterate through each file listing to download
        for _, download_url in items:
            self.log.info(f"Downloading codebase {download_url}")

            # Extract the name of the file we are downloaded from the URL
            filename = get_filename_from_download_url(download_url)

            # Make sure that we support this archive type extension
            if not is_supported_archive_type(filename):
                self.log.warn(
                    'Skipping... File extension not supported for'
                    f"file: {filename}"
                )
                continue

            # Generate the download request
            page = requests.get(download_url)
            contents = page.content

            # Make sure that this archive contains at least one of the
            # vulnerable files
            found_vuln_file = False
            contents_list = list_archive_contents(filename, contents)
            for vuln_file in self.vuln_files:
                for f in contents_list:
                    try:
                        idx = f.rindex(vuln_file)
                        if idx == 0 or f[idx - 1] == os.path.sep:
                            self.log.success('Found vulnerable file: %s --> %s'
                                             %  (vuln_file, f))
                            found_vuln_file = True
                            vuln_file = f
                            break
                    except ValueError:
                        pass
                if found_vuln_file:
                    break

            if not found_vuln_file:
                self.log.fail('Unable to locate vulnerable file!')
                return

            # Make the CVE directory
            common_root = os.path.commonpath(contents_list)
            cve_dir = os.path.join(FORAGED_OUT_DIR, self.uniq_cve_dirname())
            self.log.debug('Generating CVE docker under ' + cve_dir)
            os.mkdir(cve_dir)

            # Find the common root, since we make need to create another
            # directory level
            if common_root == '':
                # Ahh the all so very frustrating age-old problem of compressing
                # the contents of a directory, rather than the directory itself!
                common_root = without_ext(filename)
                path_to_codebase = os.path.join(cve_dir, common_root)
                os.mkdir(path_to_codebase)
                # Vulnerable file path needs to update, since the directory we
                # create will be missing from it
                vuln_file = os.path.join(common_root, vuln_file)
            else:
                path_to_codebase = cve_dir

            # Extract the archive, and generate the properties file for
            # dockerizing this project (iterating through all permutations of
            # gaaphp options)
            extract_archive(filename, contents, path_to_codebase)
            cve_lower = self.cve.cve.lower()
            for new_template, reg_globals, sqlarity in \
                    itertools.product([False, True], repeat=3):
                # The register_globals PHP option only works for the old
                # template!
                if reg_globals and new_template:
                    continue

                # If we are only checking verifiable CVEs, then we only need to
                # run this for the working configuration.
                if self.check_only_verified and CAPABLE_OF_WORKING[cve_lower] \
                        != (new_template, reg_globals, sqlarity):
                    continue

                # Generate the .cve.properties file for this docker.
                self.generate_ini_file(
                    cve_dir,
                    cpe,
                    vuln_file,
                    reg_globals=reg_globals,
                    sqlarity=sqlarity
                )

                # Generate list of gaaphp options
                options = None
                for opt in ['new_template', 'reg_globals', 'sqlarity']:
                    if locals()[opt]:
                        if options is None:
                            options = opt
                        else:
                            options += f", {opt}"
                if options is None:
                    options = '<Default>'

                self.log.new_subtask(f"Running gaaphp with options: {options}")
                success = False
                try:
                    # Dockerize this codebase.
                    use_old_template = reg_globals or not new_template
                    if not dockerize(
                        cve_dir,
                        common_root,
                        self.log,
                        use_old_template=use_old_template
                    ):
                        self.log.error(
                            f"Unable to docker codebase for {cve_lower}"
                        )
                        continue

                    # Move the CVE docker to a new directory so that we don't
                    # overwrite each consecutive run.
                    if new_template:
                        opts_str = 'n'
                    else:
                        opts_str = 'o'
                    if reg_globals:
                        opts_str += 'g'
                    if sqlarity:
                        opts_str += 's'
                    new_cve_dir = f"{cve_lower}_{opts_str}"
                    from_dir = os.path.join(cve_dir, cve_lower)
                    to_dir = os.path.join(cve_dir, new_cve_dir)
                    self.log.debug(f"Moving {from_dir} to {to_dir}")
                    shutil.move(from_dir, to_dir)

                    # Run gaaphp analysis.
                    if not run_gaaphp(cve_dir, new_cve_dir, self.log):
                        self.log.error(
                            'ERROR: Unable to analyze codebase for '
                            f"'{new_cve_dir}'"
                        )
                        continue

                    exploits_dir = os.path.join(
                        SF_ROOT_DIR, 'comfortfuzz/exploits'
                    )
                    json_out_dir = os.path.join(
                        SF_ROOT_DIR, 'comfortfuzz/json_out'
                    )
                    cmd = [
                        'docker',
                        'run',
                        '--volume',
                        f"{exploits_dir}:/exploits",
                        '--volume',
                        f"{json_out_dir}:/json_out",
                        '--rm',
                        '-it',
                        'comfortfuzz',
                        './run_comfuzz',
                        new_cve_dir
                    ]
                    if not run_cmd(cmd, 'comfortfuzz', self.log):
                        continue

                    webapp_path = os.path.join(
                        os.path.join(cve_dir, new_cve_dir),
                        os.path.join('data', common_root)
                    )
                    # Run the exploit end-to-end.
                    if run_exploit(cve_lower, webapp_path, self.log):
                        print(self.success_msg)
                        self.log.success('Sucessfully triggered exploit')
                        success = True
                        return True
                    else:
                        self.log.fail('Failed to trigger exploit')

                    #value = input("Continue scraping? (y/N)... ")
                    #if value.lower() != 'y':
                    #    quit()

                    return False
                finally:
                    self.log.complete_subtask(success=success)

            # Assume that the rest of the downloads are various compressed
            # formats of the same codebase
            break

        # I guess we weren't able to either generate an exploit, or trigger
        # it in a running docker container.
        return False

    def find_and_download_codebases(self, dir_listing):
        folders, files = dir_listing
        for title, url in files.items():
            # Attempt to extract at least a partial version number
            p = re.compile('[^0-9\.]*([0-9]([0-9\.]*[0-9])?)[^0-9\.]*')
            m = p.match(title)
            if not bool(m):
                continue

            # Found a potential version number to check for
            pot_vers = version.parse(m.group(1))
            if type(pot_vers) == LegacyVersion:
                self.log.error(f"Unexpected legacy version '{pot_vers}'")
                continue

            # TODO: This is not really complete since it doesn't account for
            # extras (i.e. rc1, rc2, beta, etc...)
            for vers_range in self.valid_version_ranges:
                if vers_range.check(pot_vers):
                    self.log.success(
                        f"Matched version {pot_vers}, url=[{url}]"
                    )
                    if self.download_codebase(
                        url, self.cpe_map[vers_range], True
                    ):
                        return True

        for title, url in folders.items():
            try:
                pot_vers = version.parse(title)
                if type(pot_vers) == LegacyVersion:
                    raise InvalidVersionFormat
                for vers_range in self.valid_version_ranges:
                    if vers_range.check(pot_vers):
                        self.log.success(
                            f"Matched version {pot_vers}, url=[{url}]",
                        )
                        if self.download_codebase(
                            url, self.cpe_map[vers_range], False
                        ):
                            return True
            except InvalidVersionFormat:
                msg = f"Finding matching versions in directory '{title}', " \
                      f"where url={SOURCEFORGE_BASE_URL}/{url})..."
                self.log.new_subtask(msg)
                success = False
                try:
                    dir_listing = SourceforgeScraper.get_codebase_listing(url)
                    print_func = lambda x: self.log.info(x)
                    pretty_print_dir_contents(
                        dir_listing, print_func=print_func
                    )
                    success = self.find_and_download_codebases(dir_listing)
                finally:
                    self.log.complete_subtask(success=success)
                return success

        # If we get here, then we were either unable to find a vulnerable
        # codebase, or we were unable to gnerate/trigger an exploit for
        # it.
        return False

    def scrape_and_run_exploit0(self, cve, first_key, second_key):
        name_to_search = SourceforgeScraper.search_for_name(
            cve.description, first_key, second_key
        )

        if name_to_search is not None:
            self.log.info(f"Searching for codebase '{name_to_search}'...")
            results_map = SourceforgeScraper.find_codebase(name_to_search)
            k = 0
            for key, value in results_map.items():
                if fuzz.ratio(key, name_to_search) < 65:
                    self.log.fail(
                        f"Skipping project '{key}' due to fuzzy mismatch",
                    )
                    raise StepFailedException
                else:
                    self.log.success(
                        f"Found potential (fuzzy) match: '{key}' ~ "
                        f"'{name_to_search}'",
                    )
                    dir_listing = SourceforgeScraper.get_codebase_listing(
                        os.path.join(value, 'files')
                    )
                    self.log.info(
                        'Getting the directory listing for '
                        f"{SOURCEFORGE_BASE_URL}{value}..."
                    )
                    print_func = lambda x: self.log.info(x)
                    pretty_print_dir_contents(
                        dir_listing, print_func=print_func
                    )
                    if self.find_and_download_codebases(dir_listing):
                        return True
                    if k > 5:
                        self.log.warn('Skipping... Too many results!')
                        return False
                    k = k + 1

    def scrape_and_run_exploit(self):
        # Is an SQL injection possible?
        inj_possible = False

        cve = self.cve
        vuln_files = self.vuln_files
        valid_version_ranges = self.valid_version_ranges
        cpe_map = self.cpe_map

        for cwe in cve.get_cwes():
            try:
                idx = cwe.index('CWE-')
                if idx != 0:
                    inj_possible = True
                if int(cwe[4:]) == 89:
                    inj_possible = True
            except ValueError:
                inj_possible = True

        if not inj_possible:
            return

        if len(vuln_files) > 0:
            # An SQL injection is possible, and there is one or more
            # vulnerable PHP files found.
            first_vals = set()
            second_vals = set()
            for cpe_info in cve.cpe_list_flat:
                cpe_split = cpe_info[0].split(':')
                first_vals.add(cpe_split[3])
                second_vals.add(cpe_split[4])
                version_minor = cpe_split[6]
                version_range = compute_version_range(
                    cpe_split[5], cpe_info[1], cpe_info[2]
                )
                if version_minor != '*':
                    # Just write over the lower/upper extra, because
                    # I've found no consistency with the minor version
                    # as listed in the CPE!
                    if (not version_range.lower.any):
                        version_range.lower.extra = version_minor
                    if (not version_range.upper.any):
                        version_range.upper.extra = version_minor
                valid_version_ranges.append(version_range)
                cpe_map[version_range] = cpe_info[0]

            ranges_str = ', '.join([str(x) for x in valid_version_ranges])
            self.log.new_task(
                'Discovered plausible SQL injection attack vector'
                ' affecting the following versions:\n\n' + ranges_str,
                title=cve.cve
            )
            success_outer = True
            try:
                for first_key in first_vals:
                    for second_key in second_vals:
                        self.log.new_subtask(
                            'Searching sourceforge for codebase matching '
                            f"{first_key}:{second_key}"
                        )
                        try:
                            success_inner = \
                                    self.scrape_and_run_exploit0(cve, first_key,
                                                                 second_key)
                            break
                        except StepFailedException:
                            # Don't log these since it's obvious from the
                            # output that a step failed
                            success_inner = False
                        except:
                            success_inner = False
                            self.log.log_exception(traceback.format_exc())
                        finally:
                            self.log.complete_subtask(
                                msg=f"Ending search of {first_key}:{second_key}",
                                success=success_inner
                            )
            except StepFailedException:
                # Don't log these since it's obvious from the output that a
                # step failed
                success_outer = False
            except:
                success_outer = False
                self.log.log_exception(traceback.format_exc())
            finally:
                self.log.complete_task(success=success_outer)
