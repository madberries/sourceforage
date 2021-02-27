import re

from enum import IntEnum
from packaging import version

class InvalidVersionFormat(Exception):
    pass

class Op(IntEnum):
    LE = 1
    LT = 2
    EQ = 3
    GT = 4
    GE = 5

op_map     = {
        '<': Op.LT,
        '<=': Op.LE,
        '=': Op.EQ,
        '>': Op.GT,
        '>=': Op.GE
}
inv_op_map = { v : k for k, v in op_map.items() }

class Version:
    def __init__(self, vers):
        vers = vers.strip()
        if vers == '*':
            self.any = True
        else:
            self.any = False
            if vers.startswith('<') or vers.startswith('>'):
                p = re.compile('((<|>)=?)\s*([0-9\.]+)(.*)')
                m = p.match(vers)
                if not bool(m):
                    raise InvalidVersionFormat(vers)
                self.op = op_map[m.group(1)]
                self.vers = m.group(3)
                self.extra = m.group(4)
            else:
                self.op = Op.EQ
                p = re.compile('([0-9\.]+)(.*)')
                m = p.match(vers)
                if not bool(m):
                    raise InvalidVersionFormat(vers)
                self.vers = m.group(1)
                self.extra = m.group(2)
            self.parsed = version.parse(self.vers)
            self.full = self.vers + self.extra
    def check(self, vers):
        assert(not vers.any and vers.op is Op.EQ)
        if self.any:
            return True
        print('Checking %s %s %s' % (vers.vers, inv_op_map[self.op], self.vers))
        if self.op is Op.LE:
            return vers.parsed <= self.parsed
        if self.op is Op.LT:
            return vers.parsed < self.parsed
        if self.op is Op.EQ:
            return vers.parsed == self.parsed
        if self.op is Op.GT:
            return vers.parsed > self.parsed
        if self.op is Op.GE:
            return vers.parsed >= self.parsed
        assert(false), 'Invalid operator: ' + self.op
    def __str__(self):
        if self.any:
            return '*'
        return self.full

class VersionRange:
    def __init__(self, lower, upper):
        self.lower = lower
        self.upper = upper
    def check(self, vers):
        return self.lower.check(vers) and self.upper.check(vers)
    def __str__(self):
        if self.lower.any or self.lower.op is Op.GE:
            if self.upper.any or self.upper.op is Op.LE:
                return '[%s .. %s]' % (self.lower, self.upper)
            assert(not self.upper.any and self.upper.op is Op.LT)
            return '[%s .. %s)' % (self.lower, self.upper)
        assert(not self.lower.any and self.lower.op is Op.GT)
        if self.upper.any or self.upper.op is Op.LE:
            return '(%s .. %s]' % (self.lower, self.upper)
        assert(not self.upper.any and self.upper.op is Op.LT)
        return '(%s .. %s)' % (self.lower, self.upper)

def compute_version_range(vers, lower_bound, upper_bound):
    vers_obj = Version(vers)
    if not vers_obj.any:
        assert(vers_obj.op is Op.EQ)
        assert(lower_bound == '*' and upper_bound == '*')
        return VersionRange(vers_obj, vers_obj)
    else:
        lower_version = Version(lower_bound)
        upper_version = Version(upper_bound)
        assert(lower_version.any or lower_version.op >= Op.GT), lower_version.vers
        assert(upper_version.any or upper_version.op <= Op.LT), upper_version.vers
        assert(lower_version.any or upper_version.any or \
                lower_version.parsed <= upper_version.parsed), \
                '%s > %s' % (lower_version.vers, upper_version.vers)
        return VersionRange(lower_version, upper_version)

