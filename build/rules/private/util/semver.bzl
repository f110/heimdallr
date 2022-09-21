def _calc_base(ver):
    base = 10
    for i in range(1, 5):
        if ver.major < base and ver.minor < base and ver.patch < base:
            return base
        base = base * 10 * i
    return 0

def _product(base, ver):
    return ver.major * base * base + ver.minor * base + ver.patch

def _parse(ver):
    normalized = ver
    if ver[0] == "v":
        normalized = ver[1:]

    s = normalized.split(".")
    if len(s) == 3:
        if not s[0].isdigit() or not s[1].isdigit() or not s[2].isdigit():
            return

        major = int(s[0])
        minor = int(s[1])
        patch = int(s[2])

        return struct(
            major = major,
            minor = minor,
            patch = patch,
        )
    elif len(s) == 2:
        if not s[0].isdigit() or not s[1].isdigit():
            return

        major = int(s[0])
        minor = int(s[1])
        return struct(
            major = major,
            minor = minor,
            patch = 0,
        )

def _equal(left, right):
    if left.major == right.major and left.minor == right.minor and left.patch == right.patch:
        return True
    return False

def _gt(left, right):
    left_base = _calc_base(left)
    right_base = _calc_base(right)
    base = left_base
    if left_base < right_base:
        base = right_base

    if _product(base, left) > _product(base, right):
        return True
    return False

def _lt(left, right):
    left_base = _calc_base(left)
    right_base = _calc_base(right)
    base = left_base
    if left_base < right_base:
        base = right_base

    if _product(base, left) < _product(base, right):
        return True
    pass

def _gte(left, right):
    if _equal(left, right):
        return True
    return _gt(left, right)

def _lte(left, right):
    if _equal(left, right):
        return True
    return _lt(left, right)

semver = struct(
    parse = _parse,
    equal = _equal,
    gt = _gt,
    lt = _lt,
    gte = _gte,
    lte = _lte,
)
