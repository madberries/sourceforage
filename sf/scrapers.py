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
from enum import Enum
from fuzzywuzzy import fuzz
from packaging import version
from packaging.version import LegacyVersion
from pathlib import Path
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


class Status(Enum):
    CODEBASE_NOT_FOUND = 1
    NO_INJECTION = 2
    VAGUE = 3
    FAIL = 4
    PASS = 5


class SourceforgeScraper:

    def __init__(
        self,
        cve,
        log,
        check_only_verified=False,
        success_msg='Exploit succeeded!',
        prompt=False
    ):
        self.cve = cve
        self.log = log
        self.check_only_verified = check_only_verified
        self.success_msg = success_msg
        self.prompt = prompt
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
    def find_codebase(project_name, page=1):
        results_map = dict()
        project_name = urllib.parse.quote(project_name)
        page = requests.get(
            f"{SOURCEFORGE_BASE_URL}/directory/language:php"
            f"/?q={project_name}&page={page}"
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
                            self.log.success(
                                'Found vulnerable file: %s --> %s' %
                                (vuln_file, f)
                            )
                            found_vuln_file = True
                            vuln_file = f
                            break
                    except ValueError:
                        pass
                if found_vuln_file:
                    break

            # TODO: Currently we only consider the first vulnerable file that
            #       we find in the description, but we may way to individually
            #       try analyzing each one (in case we fail to find the
            #       vulnerability in the first vulnerable file).
            if not found_vuln_file:
                self.log.fail('Unable to locate vulnerable file!')
                return None

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
                    new_cve_dirname = f"{cve_lower}_{opts_str}"
                    old_cve_dir = os.path.join(cve_dir, cve_lower)
                    new_cve_dir = os.path.join(cve_dir, new_cve_dirname)
                    self.log.debug(f"Moving {old_cve_dir} to {new_cve_dir}")
                    shutil.move(old_cve_dir, new_cve_dir)

                    # Run gaaphp analysis.
                    if not run_gaaphp(cve_dir, new_cve_dirname, self.log):
                        self.log.error(
                            'Unable to analyze codebase for '
                            f"'{new_cve_dirname}'"
                        )
                        continue

                    # If analysis was successful, then run comfortfuzz to
                    # generate an exploit for the discovered vulnerability.
                    volume_dir = os.path.abspath(new_cve_dir)
                    cmd = [
                        'docker',
                        'run',
                        '--volume',
                        f"{volume_dir}:/app",
                        '--rm',
                        '-it',
                        'comfortfuzz',
                        './run_comfuzz',
                        new_cve_dirname
                    ]
                    if not run_cmd(cmd, 'comfortfuzz', self.log):
                        continue

                    # Run the exploit end-to-end.
                    webapp_path = os.path.join(
                        new_cve_dir, os.path.join('data', common_root)
                    )
                    if run_exploit(cve_lower, webapp_path, self.log):
                        print(self.success_msg)
                        self.log.success('Sucessfully triggered exploit')
                        success = True
                        # Mark this in the FS so that we can easily query the
                        # successes at a later date
                        Path(new_cve_dir, '.success').touch()
                        return True
                    else:
                        self.log.fail('Failed to trigger exploit')

                    # If we got this far (but somehow failed to get a working
                    # exploit) and we should prompt the user before continuing,
                    # then block here such that the user can determine the
                    # source of the problem by manually running the exploit by
                    # hand in a running docker (via the 'runexploit' command).
                    if self.prompt:
                        value = input("Continue scraping? (y/N)... ")
                        if value.lower() != 'y':
                            sys.exit(0)

                    return False
                finally:
                    self.log.complete_subtask(success=success)

            # Assume that the rest of the downloads are various compressed
            # formats of the same codebase
            break

        # I guess we weren't able to either generate an exploit, or trigger
        # it in a running docker container.
        return False

    # Possible return values:
    #  - None: No codebase was found
    #  - False: Codebase found, but no exploit was generate (or failed to work end-to-end)
    #  - True: Codebase was found and exploit worked end-to-end
    def find_and_download_codebases(self, dir_listing):
        result = None
        folders, files = dir_listing

        # First try the lower-hanging fruit (i.e. the files).
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
                    self.log.success(f"Matched version {pot_vers}, url=[{url}]")
                    tmp_result = self.download_codebase(
                        url, self.cpe_map[vers_range], True
                    )
                    if tmp_result:    # None is interpretted as False.
                        return True
                    # Now tmp_result here must be None or False
                    if result is None:
                        result = tmp_result

        # Then try the higher to reach fruit (i.e. the directories).
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
                        tmp_result = self.download_codebase(
                            url, self.cpe_map[vers_range], False
                        )
                        if tmp_result:    # None is interpretted as False.
                            return True
                        # Now tmp_result here must be None or False
                        if result is None:
                            result = tmp_result
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
                    tmp_result = self.find_and_download_codebases(dir_listing)
                    if tmp_result:    # None is interpretted as False.
                        success = True
                        return True
                    # Now tmp_result here must be None or False
                    if result is None:
                        result = tmp_result
                finally:
                    self.log.complete_subtask(success=success)

        return result

    def scrape_and_run_exploit0(self, cve, vendors, product):
        # TODO: Maybe the vendor information can aid us in the search,
        #       but it appears to me that the product information is
        #       enough to go on...
        name_to_search = SourceforgeScraper.search_for_name0(
            cve.description, product
        )

        result = None
        if name_to_search is not None:
            self.log.info(f"Searching for codebase '{name_to_search}'...")
            page = 1
            while True:
                results_map = SourceforgeScraper.find_codebase(
                    name_to_search, page
                )
                if len(results_map) == 0:
                    self.log.info('No more codebases to search')
                    break
                k = 0
                for key, value in results_map.items():

                    if fuzz.ratio(key, name_to_search) < 65:
                        self.log.fail(
                            f"Skipping project '{key}' due to fuzzy mismatch",
                        )
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

                        # Find the codebase starting at the root directory
                        # listing.
                        tmp_result = self.find_and_download_codebases(
                            dir_listing
                        )
                        if tmp_result:    # None is interpretted as False.
                            return True
                        # Now tmp_result here must be None or False
                        if result is None:
                            result = tmp_result

                        # Don't check more than five matching codebases for now
                        # but we may want to make this configurable.
                        if k > 5:
                            self.log.warn('Skipping... Too many results!')
                            return result
                        k = k + 1
                page += 1
        return result

    def scrape_and_run_exploit(self):
        # Is an SQL injection possible?
        inj_possible = False

        cve = self.cve
        vuln_files = self.vuln_files
        valid_version_ranges = self.valid_version_ranges
        cpe_map = self.cpe_map

        # Verify that an SQL injection is possible.
        # TODO: Should we also consider general CVEs with (i.e. where the
        #       number is unspecified??)
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
            return Status.NO_INJECTION

        # The injection was possible, but are there vulnerable files?
        if len(vuln_files) == 0:
            return Status.VAGUE
        else:
            # An SQL injection is possible, and there is one or more
            # vulnerable PHP files found.
            vendors = set()
            products = set()
            for cpe_info in cve.cpe_list_flat:
                cpe_split = cpe_info[0].split(':')
                vendors.add(cpe_split[3])
                products.add(cpe_split[4])
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
            self.log.new_subtask(
                'Discovered plausible SQL injection attack vector'
                ' affecting the following versions:\n\n' + ranges_str,
                title=cve.cve
            )

            # Print out the CPE map (in case it's useful).
            self.log.debug('CPE map:\n--------\n')
            self.log.debug(
                '\n'.join([f"{x[0]}: {x[1]}" for x in cpe_map.items()])
            )

            if len(vendors) == 1:
                vendors_str = vendors.pop()
            else:
                vendors_str = ','.join(vendors)
                vendors_str = f"{{{vendors_str}}}"

            success_outer = True
            result = None
            try:
                for product in products:
                    success_inner = True
                    self.log.new_subtask(
                        'Searching sourceforge for codebase matching '
                        f"{vendors_str}:{product}"
                    )
                    try:
                        tmp_result = \
                                self.scrape_and_run_exploit0(cve, vendors, product)
                        if tmp_result:    # None is interpretted as False.
                            success_inner = True
                            result = True
                            break
                        # Now tmp_result here must be None or False
                        if result is None:
                            result = tmp_result
                    # TODO: Re-implement me... This was to account for an odd
                    #       corner-case and handle a sys.exit() gracefully. But
                    #       I guess we really should not have to catch all
                    #       exceptions, and instead we should just know ahead
                    #       of time which exceptions can be thrown here...
                    except SystemExit:
                        raise
                    except StepFailedException:
                        # Don't log these since it's obvious from the
                        # output that a step failed
                        success_inner = False
                    except:
                        success_inner = False
                        self.log.log_exception(traceback.format_exc())
                    finally:
                        self.log.complete_subtask(
                            msg=f"Ending search of {vendors_str}:{product}",
                            success=success_inner
                        )
            # TODO: Re-implement me... This was to account for an odd corner-
            #       case and handle a sys.exit() gracefully. But I guess we
            #       really should not have to catch all exceptions, and instead
            #       we should just know ahead of time which exceptions can be
            #       thrown here...
            except SystemExit:
                raise
            except StepFailedException:
                # Don't log these since it's obvious from the output that a
                # step failed
                success_outer = False
            except:
                success_outer = False
                self.log.log_exception(traceback.format_exc())
            finally:
                self.log.complete_subtask(success=success_outer)

            # Finally return the status of the completed run.
            if result is None:
                return Status.CODEBASE_NOT_FOUND
            elif result:
                return Status.PASS
            else:
                return Status.FAIL
