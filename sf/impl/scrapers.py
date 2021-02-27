import os
import itertools
import re
import requests
import selectors
import shutil
import sys
import urllib.parse

from bs4 import BeautifulSoup
from datetime import datetime
from fuzzywuzzy import fuzz

from .analysis import run_gaaphp
from .dockerizer import dockerize
from .exploit_runner import run_exploit
from .versions import Version, InvalidVersionFormat, compute_version_range
from .helpers.constants import CAPABLE_OF_WORKING, FORAGED_OUT_DIR, \
                               HACCSCMD_ROOT_DIR
from .helpers.file_utils import get_filename_from_download_url, without_ext
from .helpers.process_utils import run_cmd
from .helpers.string_utils import border, contains_substr
from .helpers.zip_utils import extract_archive, is_supported_archive_type, \
                               list_archive_contents

class SourceforgeScraper:
    def __init__(self, cve, check_only_verified=False, success_msg='Exploit succeeded!'):
        self.cve = cve
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
            return desc[search_idx : search_idx + len(name)]
        for replace in [ ' ', '-' ]:
            search_idx = contains_substr(desc, name.replace('_', replace))
            if search_idx >= 0:
                return desc[search_idx : search_idx + len(name)]
        return None

    @staticmethod
    def search_for_name(desc, first, second):
        if first != second:
            result = SourceforgeScraper.search_for_name0(desc,
                                                         first + ' ' + second)
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
        page = requests.get('https://sourceforge.net/directory/language:php/?q='
                + urllib.parse.quote(project_name))
        contents = page.content
        soup = BeautifulSoup(contents, 'html.parser')
        projects = soup.find_all('a', {'class': 'result-heading-title'})
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

        print('Getting the %s listing of %s' % (listing_type, rel_path))
        page = requests.get('https://sourceforge.net' + rel_path)
        contents = page.content
        soup = BeautifulSoup(contents, 'html.parser')

        # Construct a listing of all file/folder -> url mappings found
        # on this page.
        for entity_type, entity_map in \
                [('folder', folders_map), ('file', files_map)]:
            entities = soup.find_all('tr', {'class': entity_type})
            for entity in entities:
                title = entity.get('title')
                if title is not None:
                    entity_map[title] = entity.th.a.get('href')

        return folders_map, files_map

    def download_codebase(self, url, cpe, is_file):
        # If the url provided was from a file listing, then the URL provided
        # should already be the download URL
        if is_file:
            items = [ ('N/A', url) ]
        else:
            items = SourceforgeScraper.get_codebase_file_listing(url).items()

        # Iterate through each file listing to download
        for _, download_url in items:
            print('Downloading codebase ' + download_url)

            # Extract the name of the file we are downloaded from the URL
            filename = get_filename_from_download_url(download_url)

            # Make sure that we support this archive type extension
            if not is_supported_archive_type(filename):
                print('Skipping... File extension not supported for file: '
                        + filename)
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
                        if idx == 0 or f[idx-1] == os.path.sep:
                            print('Found vulnerable file: %s --> %s' % \
                                    (vuln_file, f))
                            found_vuln_file = True
                            vuln_file = f
                            break
                    except ValueError:
                        pass
                if found_vuln_file:
                    break

            if not found_vuln_file:
                print('Unable to locate vulnerable file!')
                return

            # Make the CVE directory
            common_root = os.path.commonpath(contents_list)
            cve_dir = os.path.join(FORAGED_OUT_DIR, self.uniq_cve_dirname())
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
                self.generate_ini_file(cve_dir, cpe, vuln_file,
                                       reg_globals=reg_globals,
                                       sqlarity=sqlarity)

                # Dockerize this codebase.
                use_old_template = reg_globals or not new_template
                if not dockerize(cve_dir, common_root,
                                 use_old_template=use_old_template):
                    print('ERROR: Unable to docker codebase for ' + cve_lower,
                          file=sys.stderr)
                    continue

                # Move the CVE docker to a new directory so that we don't
                # overwrite each consecutive run.
                if reg_globals:
                    if sqlarity:
                        new_cve_dir = cve_lower + '_gs'
                    else:
                        new_cve_dir = cve_lower + '_g'
                elif sqlarity:
                    new_cve_dir = cve_lower + '_s'
                else:
                    new_cve_dir = cve_lower + '_noargs'
                shutil.move(os.path.join(cve_dir, cve_lower),
                            os.path.join(cve_dir, new_cve_dir))

                # Run gaaphp analysis.
                if not run_gaaphp(cve_dir, new_cve_dir):
                    print('ERROR: Unable to analyze codebase for "%s"' %
                           new_cve_dir, file=sys.stderr)
                    continue

                exploits_dir = os.path.join(HACCSCMD_ROOT_DIR,
                                            'comfortfuzz/exploits')
                json_out_dir = os.path.join(HACCSCMD_ROOT_DIR,
                                            'comfortfuzz/json_out')
                cmd = ['docker', 'run', '--volume', exploits_dir + ':/exploits',
                        '--volume', json_out_dir + ':/json_out', '--rm', '-it',
                        'comfortfuzz', './run_comfuzz', new_cve_dir]
                if not run_cmd(cmd, 'comfortfuzz'):
                    continue

                webapp_path = os.path.join(os.path.join(cve_dir, new_cve_dir),
                        os.path.join('data', common_root))
                # Run the exploit end-to-end.
                if run_exploit(cve_lower, webapp_path):
                    print(self.success_msg)
                else:
                    print('***FAILURE: exploit was not exercised!***')

                value = input("Continue scraping? (y/N)... ")
                if value.lower() != 'y':
                    quit()
            break

    def find_and_download_codebases(self, dir_listing):
        folders, files = dir_listing
        for title, url in files.items():
            # Attempt to extract at least a partial version number
            p = re.compile('[^0-9\.]*([0-9]([0-9\.]*[0-9])?)[^0-9\.]*')
            m = p.match(title)
            if not bool(m):
                continue

            # Found a potential version number to check for
            pot_vers = Version(m.group(1))

            # TODO: This is not really complete since it doesn't account for
            # extras (i.e. rc1, rc2, beta, etc...)
            for vers_range in self.valid_version_ranges:
                if vers_range.check(pot_vers):
                    print('Checking version %s, url=[%s]' % (pot_vers, url))
                    self.download_codebase(url, self.cpe_map[vers_range], True)

        for title, url in folders.items():
            try:
                pot_vers = Version(title)
                for vers_range in self.valid_version_ranges:
                    if vers_range.check(pot_vers):
                        print('Checking version %s, url=[%s]' % (pot_vers, url))
                        self.download_codebase(url, self.cpe_map[vers_range], False)
            except InvalidVersionFormat:
                print('Finding versions in ' + title)
                self.find_and_download_codebases(
                        SourceforgeScraper.get_codebase_listing(url))

    def scrape_and_run(self):
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
                    inj_possible = True;
            except ValueError:
                inj_possible = True

        if not inj_possible:
            return

        if len(vuln_files) > 0:
            # An SQL injection is possible, and there is one or more
            # vulnerable PHP files found.
            first = set()
            second = set()
            for cpe_info in cve.cpe_list_flat:
                cpe_split = cpe_info[0].split(':')
                first.add(cpe_split[3])
                second.add(cpe_split[4])
                version_minor = cpe_split[6]
                version_range = compute_version_range(
                        cpe_split[5], cpe_info[1], cpe_info[2])
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

            for f in first:
                for s in second:
                    print(border('Starting search for %s:%s in %s' % \
                            (f, s, cve.cve)))
                    name_to_search = \
                        SourceforgeScraper.search_for_name(cve.description,
                                                           f, s)
                    if name_to_search is not None:
                        print('Searching for codebase "%s"...' % name_to_search)
                        k = 0
                        results_map = \
                            SourceforgeScraper.find_codebase(name_to_search)
                        for key, value in results_map.items():
                            if fuzz.ratio(key, name_to_search) < 65:
                                print('Skipping project "%s" due to fuzzy '
                                      'mismatch' % key)
                                continue
                            else:
                                print('Matched fuzzy "%s" ~= "%s"' %
                                      (key, name_to_search))
                            dir_listing = \
                                SourceforgeScraper.get_codebase_listing(
                                        os.path.join(value, 'files'))
                            self.find_and_download_codebases(dir_listing)
                            if k > 5:
                                print('Skipping... Too many results!')
                                break
                            k = k + 1
