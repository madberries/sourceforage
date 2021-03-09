import os

# The root directory of 'sourceforage'.
SF_ROOT_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
)

SOURCEFORGE_BASE_URL = 'https://sourceforge.net'

# Output directory for downloaded codebases
FORAGED_OUT_DIR = 'foraged'

# Timeouts
EXPLOIT_TIMEOUT = 30    # The timeout for an exploit to run
GAAPHP_TIMEOUT = 30    # The timeout for an analysis to run

# Common configuration filenames to search for
POSSIBLE_CONFIG_NAMES = ['common.php', 'config.php']

# Default DB information
DBHOST = 'localhost'
DBNAME = 'somedb'
DBUSER = 'root'
DBPASS = ''

# Application admin credentials
ADMINUSER = 'admin'
ADMINPASS = 'admin'

# Common Regexes:
MYSQL_REGEX = r'(mysql|db|d(ata)base)?'
HOST_REGEX = r'(host(_?)(name)?)|address'
USER_REGEX = r'user(_?)(name)?'
PASS_REGEX = r'pass(word)?'
DBNAME_REGEX = r'(d(ata)base|(?!(user|host))(db)?name)'

# Possible Var X Value (i.e. cartesian product) of possible configuration
# replacements
DBHOST_REPLACEMENTS = [
    [rf'{MYSQL_REGEX}(_?){HOST_REGEX}', HOST_REGEX],
    [DBHOST]
]  # yapf: disable
DBUSER_REPLACEMENTS = [
    [rf'{MYSQL_REGEX}(_?){USER_REGEX}', USER_REGEX],
    [DBUSER]
]  # yapf: disable
DBNAME_REPLACEMENTS = [
    [rf'{MYSQL_REGEX}(_?){DBNAME_REGEX}', r'default_db|(d(ata)base)'],
    [DBNAME]
]  # yapf: disable
DBPASS_REPLACEMENTS = [
    [rf'{MYSQL_REGEX}(_?){PASS_REGEX}', PASS_REGEX],
    [DBPASS]
]  # yapf: disable
# Consider the case where the url ends with a forward slash as well as
# the case without it, since the app might not properly check for this.
DBROOT_REPLACEMENTS = [
    ['([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)?(_(path|root))'],
    [
        (r'\7/', '(http://(localhost|127\.0\.0\.1))/[^/]+/'),
        (r'\7', '(http://(localhost|127\.0\.0\.1))/[^/]+')
    ]
]  # yapf: disable

# Default HTTP server configuration
HTTP_SERVER_ADDR = '172.17.0.1'
HTTP_SERVER_PORT = 5000

# List of supported archive extensions:
#
# TODO: We might want to consider supporting additional ones (like rar and 7z)
SUPPORTED_EXTS = ['.zip', '.tar.gz', '.tgz', '.tar.bz2', '.rar']

# Dictionary of CVEs capable of working end-to-end (where the mapping is the
# CVE name to it's working configuration), and of the form:
#
#     "CVE-####-####": (new?, register_globals?, sqlarity?)
CAPABLE_OF_WORKING = {
    "cve-2005-2466": (False, True, False),
    "cve-2006-0074": (False, False, True),
    "cve-2006-0079": (False, True, False),
    "cve-2006-0135": (False, False, False),
    "cve-2006-1271": (False, False, False),
    "cve-2006-1481": (False, False, False),
    "cve-2006-7088": (True, False, True),
    "cve-2007-3534": (False, True, False),
    "cve-2008-0154": (False, False, True),
    "cve-2008-0159": (True, False, False),
    "cve-2008-0424": (True, False, True),
    "cve-2008-0677": (True, False, True),
    "cve-2008-4092": (False, True, False),
    "cve-2008-6081": (True, False, True),
    "cve-2008-6142": (True, False, False),
    "cve-2009-0881": (False, False, False),
    "cve-2009-1500": (True, False, False),
    "cve-2009-1814": (False, False, True),
    "cve-2009-2036": (False, True, False),
    "cve-2009-2096": (False, False, False),
    "cve-2010-1538": (True, False, False),
    "cve-2010-4876": (True, False, False),
    "cve-2010-4935": (True, False, False),
    "cve-2014-9440": (True, False, True),
    "cve-2015-1372": (True, False, False),
}
