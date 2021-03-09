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
from .exploit import run_exploit
from .version import VersionCondition, InvalidVersionFormat, \
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
            # We have to check .php. extensions too, since the mentioned
            # PHP file could be the last word in a sentence.
            elif word.endswith('.php.'):
                self.vuln_files.add(word[:-1])
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
        dir_listing = \
                SourceforgeScraper.get_codebase_listing(rel_path,
                                                        listing_type="file")
        if dir_listing is None:
            return None
        _, files = dir_listing
        return files

    @staticmethod
    def get_codebase_dir_listing(rel_path):
        dir_listing = \
                SourceforgeScraper.get_codebase_listing(rel_path,
                                                        listing_type='folder')
        if dir_listing is None:
            return None
        folders, _ = dir_listing
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
        if page.status_code != 200:
            return None
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
            if items is None:
                # Only soft fail such that we continue our search.
                self.log.soft_fail(f'Broken link: {url}')
                return None

        # Iterate through each file listing to download
        for _, download_url in items:
            self.log.info(f"Downloading codebase {download_url}")

            # Extract the name of the file we are downloaded from the URL
            filename = get_filename_from_download_url(download_url)

            # Make sure that we support this archive type extension
            if not is_supported_archive_type(filename):
                self.log.soft_fail(
                    'Skipping... File extension not supported for file: ' +
                    filename
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
                # I guess we can't presume that the other archives found in the
                # same directory can't be the codebase with the vulnerable file,
                # and so only soft fail here to continue checking within the
                # same directory
                self.log.soft_fail('Unable to locate vulnerable file!')
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

                self.log.new_substep(
                    f"Running gaaphp with options: {options}",
                    caption='analysis'
                )
                try:
                    # Dockerize this codebase.
                    use_old_template = reg_globals or not new_template
                    if not dockerize(
                        cve_dir,
                        common_root,
                        self.log,
                        use_old_template=use_old_template
                    ):
                        self.log.hard_fail(
                            f"Unable to docker codebase for {cve_lower}"
                        )

                    # Move the CVE docker into a new directory so that we don't
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
                        self.log.hard_fail(
                            'Unable to analyze codebase for '
                            f"'{new_cve_dirname}'"
                        )

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
                        self.log.hard_fail(
                            'Unable to run comfortfuzz on discovered '
                            'vulnerability'
                        )

                    # Run the exploit end-to-end.
                    webapp_path = os.path.join(
                        new_cve_dir, os.path.join('data', common_root)
                    )
                    if run_exploit(cve_lower, webapp_path, self.log):
                        print(self.success_msg)
                        self.log.success('Sucessfully triggered exploit')
                        # Mark this in the FS so that we can easily query the
                        # successes at a later date
                        Path(new_cve_dir, '.success').touch()
                        return True
                    else:
                        self.log.soft_fail('Failed to trigger exploit')

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
                # TODO: Re-implement me... This was to account for an odd corner-
                #       case and handle a sys.exit() gracefully. But I guess we
                #       really should not have to catch all exceptions, and instead
                #       we should just know ahead of time which exceptions can be
                #       thrown here...
                except SystemExit:
                    raise
                except StepFailedException:
                    # Don't re-raise the exception, since we only want to fail
                    # across this substep
                    pass
                except:
                    self.log.log_exception(traceback.format_exc())
                finally:
                    self.log.complete_substep()

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
                self.log.new_substep(msg, caption=title)
                try:
                    # Log the directory listing of the current working
                    # directory on sourceforge.
                    dir_listing = SourceforgeScraper.get_codebase_listing(url)
                    if dir_listing is None:
                        self.log.hard_fail(f'Broken link: {url}')

                    print_func = lambda x: self.log.info(x)
                    pretty_print_dir_contents(
                        dir_listing, print_func=print_func
                    )

                    # Recursively search the directory tree.
                    tmp_result = self.find_and_download_codebases(dir_listing)
                    if tmp_result:    # None is interpretted as False.
                        self.log.success(
                            f"Triggered working exploit for '{title}'"
                        )
                        return True
                    else:
                        if tmp_result is None:
                            fail_msg = f"No codebase found in '{title}' " \
                                        'directory'
                        else:
                            fail_msg = 'Failed to trigger exploit for a ' \
                                       f"codebase discovered in '{title}' " \
                                       'directory'
                        self.log.soft_fail(fail_msg)
                    # Now tmp_result here must be None or False
                    if result is None:
                        result = tmp_result
                # TODO: Re-implement me... This was to account for an odd corner-
                #       case and handle a sys.exit() gracefully. But I guess we
                #       really should not have to catch all exceptions, and instead
                #       we should just know ahead of time which exceptions can be
                #       thrown here...
                except SystemExit:
                    raise
                except StepFailedException:
                    # Don't re-raise the exception, since we only want to fail
                    # across this substep
                    pass
                except:
                    self.log.log_exception(traceback.format_exc())
                finally:
                    self.log.complete_substep(
                        msg=f"Finished searching '{title}' directory"
                    )

        return result

    def scrape_and_run_exploit0(self, cve, vendors, product):
        # Construct a list of (perhaps likely) candidates with the hope of
        # obviating the need for a full search.
        print_func = lambda x: self.log.info(x)
        feeling_lucky = [ os.path.join('projects', product) ]
        if contains_substr(product, '-', ignore_case=False) > 0:
            feeling_lucky.append(feeling_lucky[0].replace('-', '_'))
        if contains_substr(product, '_', ignore_case=False) > 0:
            feeling_lucky.append(feeling_lucky[0].replace('_', '-'))

        # Try all of the potential project roots that seem like likely
        # candidates, and if the page exists then attempt to scrape
        # those projects.
        result = None
        for lucky_project in feeling_lucky:
            self.log.info('Feeling lucky... Attempting to get directory listing'
                          f' for {SOURCEFORGE_BASE_URL}{lucky_project}...')
            dir_listing = SourceforgeScraper.get_codebase_listing(
                os.path.join(lucky_project, 'files'))
            if dir_listing is None:
                self.log.info(
                    f"Project '{lucky_project}' not found!  Oh well, we tried."
                )
                continue
            tmp_result = self.find_and_download_codebases(
                dir_listing
            )
            if tmp_result:    # None is interpretted as False.
                return True
            # Now tmp_result here must be None or False
            if result is None:
                result = tmp_result

        # TODO: Maybe the vendor information can aid us in the search,
        #       but it appears to me that the product information is
        #       enough to go on...
        name_to_search = SourceforgeScraper.search_for_name0(
            cve.description, product
        )

        if name_to_search is not None:
            page = 1
            while True:
                self.log.info(
                    f"Searching for codebase '{name_to_search}' on page {page}"
                    '...'
                )
                results_map = SourceforgeScraper.find_codebase(
                    name_to_search, page
                )
                if len(results_map) == 0:
                    self.log.info('No more codebases to search')
                    break
                k = 0
                for key, value in results_map.items():
                    if fuzz.ratio(key, name_to_search) < 65:
                        self.log.soft_fail(
                            f"Skipping project '{key}' due to fuzzy mismatch"
                        )
                    else:
                        self.log.success(
                            f"Found potential (fuzzy) match: '{key}' ~ "
                            f"'{name_to_search}'",
                        )

                        # Get the root directory listing for the current
                        # codebase.
                        self.log.info(
                            'Getting the directory listing for '
                            f"{SOURCEFORGE_BASE_URL}{value}..."
                        )
                        dir_listing = SourceforgeScraper.get_codebase_listing(
                            os.path.join(value, 'files')
                        )
                        if dir_listing is None:
                            # Only soft fail if we couldn't obtain a directory
                            # listing, since we can just move on to the next.
                            self.log.soft_fail(
                                f'Broken like: {SOURCEFORGE_BASE_URL}{value}'
                            )
                            continue

                        # Log the directory listing for the root of the
                        # codebase.
                        pretty_print_dir_contents(
                            dir_listing, print_func=print_func
                        )

                        # Find the codebase starting at the root directory.
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
            self.log.warn(
                'No vulnerable PHP file mentioned in the CVE description!'
            )
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

            # Start a new subtask for this search.
            ranges_str = ', '.join([str(x) for x in valid_version_ranges])
            self.log.new_substep(
                'Discovered plausible SQL injection attack vector'
                ' affecting the following versions:\n\n' + ranges_str,
                caption=cve.cve
            )

            result = None
            try:
                # Print out the CPE map (in case it's useful).
                self.log.debug('CPE map:')
                self.log.debug('--------')
                for key, val in cpe_map.items():
                    self.log.debug(f"{key}: {val}")

                if len(vendors) == 1:
                    vendors_str = vendors.pop()
                else:
                    vendors_str = ','.join(vendors)
                    vendors_str = f"{{{vendors_str}}}"

                # Iterate through each potential product string to query for.
                for product in products:
                    self.log.new_substep(
                        'Searching sourceforge for codebase matching '
                        f"{vendors_str}:{product}",
                        caption=product
                    )
                    try:
                        tmp_result = \
                                self.scrape_and_run_exploit0(cve, vendors, product)
                        if tmp_result:    # None is interpretted as False.
                            result = True
                            self.log.success(
                                'Successfully triggered exploit '
                                'for vulnerable codebase '
                                'discovered for %s:%s' % (vendors_str, product)
                            )
                            break
                        else:
                            if tmp_result is None:
                                fail_msg = 'No codebase found matching '
                            else:
                                fail_msg = 'Failed to trigger exploit for a ' \
                                           'codebase matching '
                            fail_msg += f'{vendors_str}:{product}'
                            self.log.soft_fail(fail_msg)
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
                        # Don't re-raise the exception, since we only want to
                        # fail across this substep
                        pass
                    except:
                        self.log.log_exception(traceback.format_exc())
                    finally:
                        self.log.complete_substep(
                            msg=f"Ending search of {vendors_str}:{product}"
                        )

                # Go through the final result, and
                if result:
                    # Good to go!
                    self.log.success(
                        'Successfully triggered an exploit for ' + cve.cve
                    )
                else:
                    if result is None:
                        fail_msg = 'Failed to discover codebase for '
                    else:
                        fail_msg = 'Discovered codebase, but failed to ' \
                                   'trigger working exploit for '
                    fail_msg += cve.cve
                    self.log.hard_fail(fail_msg)

            # TODO: Re-implement me... This was to account for an odd corner-
            #       case and handle a sys.exit() gracefully. But I guess we
            #       really should not have to catch all exceptions, and instead
            #       we should just know ahead of time which exceptions can be
            #       thrown here...
            except SystemExit:
                raise
            except StepFailedException:
                # Don't re-raise the exception, since we only want to fail
                # across this substep
                pass
            except:
                self.log.log_exception(traceback.format_exc())
            finally:
                self.log.complete_substep(
                    msg='Finished searching for codebases for ' + cve.cve
                )

            # Finally return the status of the completed run.
            if result is None:
                return Status.CODEBASE_NOT_FOUND
            elif result:
                return Status.PASS
            else:
                return Status.FAIL
