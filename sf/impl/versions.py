import re

from enum import IntEnum
from packaging.version import parse

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

class VersionCondition:
    def __init__(self, version_cond_str):
        version_cond_str = version_cond_str.strip()
        if version_cond_str == '*':
            # Wildcard case
            self.any = True
            self.op = Op.EQ
            self.version = None
        else:
            self.any = False
            p = re.compile('((<|>)=?|=)?\s*(.*)')
            m = p.match(version_cond_str)
            if not bool(m):
                raise InvalidVersionFormat(version_cond_str)
            op = m.group(1)
            if op is None:
                op = inv_op_map[Op.EQ]
            self.op = op_map[op]
            self.version = parse(m.group(3))

    def check(self, version):
        if self.any:
            return True
        #print('Checking %s %s %s' % (vers.vers, inv_op_map[self.op], self.vers))
        if self.op is Op.LE:
            return version <= self.version
        if self.op is Op.LT:
            return version < self.version
        if self.op is Op.EQ:
            return version == self.version
        if self.op is Op.GT:
            return version > self.version
        if self.op is Op.GE:
            return version >= self.version
        assert(false), 'Invalid operator: ' + self.op

    def __str__(self):
        if self.any:
            return '*'
        op = inv_op_map[self.op]
        return f"{op} {self.version}?"

    def __repr__(self):
        return self.__str__()

class VersionRange:
    def __init__(self, lower, upper):
        # First some basic sanity checks...
        #
        # Valid inputs:
        #  - both are wildcards
        #  - both have same versions and both ops are Op.EQ
        #  - * .. <|<= [version]
        #  - >|>= [version] .. *
        #  - >|>= [version] .. <|<= [version]
        #
        # All other inputs are invalid!
        if lower.version == upper.version:
            assert(upper.op == Op.EQ and lower.op == Op.EQ)
        else:
            full_range = True
            if lower.any:
                assert(upper.any or upper.op < Op.EQ), upper
                full_range = False
            if upper.any:
                assert(lower.any or lower.op > Op.EQ), lower
                full_range = False

            if full_range:
                assert(lower.version <= upper.version)
                assert(lower.op > Op.EQ and upper.op < Op.EQ), \
                        f"lower_condition: ({lower}), upper_condition: ({upper})"
        self.lower = lower
        self.upper = upper

    def check(self, version_cond):
        return self.lower.check(version_cond) and \
               self.upper.check(version_cond)

    def __str__(self):
        # If both are a wildcard, then just print '*'.
        if self.lower.any:
            if self.upper.any:
                return '*'

        # If both versions happen to be equal, just print a single version.
        if self.lower.version == self.upper.version:
            return str(self.lower.version)

        # Otherwise, not a singleton (i.e. we print a valid range).
        if self.lower.any or self.lower.op is Op.GE:
            if self.upper.any or self.upper.op is Op.LE:
                return f"[{self.lower} .. {self.upper}]"
            return f"[{self.lower} .. {self.upper})"
        if self.upper.any or self.upper.op is Op.LE:
            return f"({self.lower} .. {self.upper}]"
        return f"({self.lower} .. {self.upper})"

    def __repr__(self):
        return self.__str__()

def compute_version_range(vers, lower_bound, upper_bound):
    vers_obj = VersionCondition(vers)
    if not vers_obj.any:
        assert(vers_obj.op is Op.EQ)
        assert(lower_bound == '*' and upper_bound == '*')
        return VersionRange(vers_obj, vers_obj)
    else:
        lower_version = VersionCondition(lower_bound)
        upper_version = VersionCondition(upper_bound)
        return VersionRange(lower_version, upper_version)

