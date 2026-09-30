"""Finite integer intervals for selected compiler-typed expressions.

Intervals over-approximate values, not feasible executions. They do not prove
reachability, aliasing, object lifetime, or absence of undefined behavior.
"""
from .clang_facts import children, typed, integer, _integer_type, WRAPPERS


def type_interval(type_name, layout):
    info = _integer_type(type_name, layout)
    if info is None:
        return None
    bits, unsigned, boolean = info
    if boolean:
        return (0, 1)
    return (0, (1 << bits) - 1) if unsigned else (-(1 << (bits - 1)), (1 << (bits - 1)) - 1)


def coerce_interval(bounds, type_name, layout):
    """Never assume a narrowing/wrapping conversion is order preserving."""
    info = _integer_type(type_name, layout)
    if bounds is None or info is None:
        return None
    low, high = bounds
    if low > high:
        return None
    bits, unsigned, boolean = info
    if boolean:
        return (0, 0) if high == low == 0 else (1, 1) if low > 0 or high < 0 else (0, 1)
    domain = type_interval(type_name, layout)
    if unsigned:
        modulus = 1 << bits
        if low // modulus == high // modulus:
            return (low % modulus, high % modulus)
        return domain
    return (low, high) if domain[0] <= low <= high <= domain[1] else None


def exact_values(bindings):
    return {key: value['lower'] for key, value in bindings.items()
            if value['lower'] == value['upper']}


def interval(node, layout, bindings, depth=0):
    if depth > 64:
        return None
    known = integer(node, layout, values=exact_values(bindings))
    if known is not None:
        return (known, known)
    kind, inner = node.get('kind'), children(node)
    result = None
    if kind == 'DeclRefExpr':
        binding = bindings.get(node.get('referencedDecl', {}).get('id'))
        if binding:
            result = (binding['lower'], binding['upper'])
    elif kind in WRAPPERS and len(inner) == 1:
        result = interval(inner[0], layout, bindings, depth + 1)
    elif kind == 'UnaryOperator' and len(inner) == 1:
        value = interval(inner[0], layout, bindings, depth + 1)
        if value is not None:
            if node.get('opcode') == '+':
                result = value
            elif node.get('opcode') == '-':
                result = (-value[1], -value[0])
            elif node.get('opcode') == '!':
                result = (1, 1) if value == (0, 0) else (0, 0) if value[0] > 0 or value[1] < 0 else (0, 1)
    elif kind == 'BinaryOperator' and len(inner) == 2:
        left, right = (interval(n, layout, bindings, depth + 1) for n in inner)
        if left is not None and right is not None:
            a, b = left
            c, d = right
            op = node.get('opcode')
            if op == '+':
                result = (a + c, b + d)
            elif op == '-':
                result = (a - d, b - c)
            elif op == '*':
                products = (a*c, a*d, b*c, b*d)
                result = (min(products), max(products))
            elif op in ('<', '<=', '>', '>=', '==', '!='):
                yes = {'<': b < c, '<=': b <= c, '>': a > d, '>=': a >= d,
                       '==': a == b == c == d, '!=': b < c or d < a}[op]
                no = {'<': a >= d, '<=': a > d, '>': b <= c, '>=': b < c,
                      '==': b < c or d < a, '!=': a == b == c == d}[op]
                result = (1, 1) if yes else (0, 0) if no else (0, 1)
            elif op in ('&&', '||'):
                left_zero, right_zero = left == (0, 0), right == (0, 0)
                left_true, right_true = a > 0 or b < 0, c > 0 or d < 0
                if op == '&&':
                    result = (0, 0) if left_zero or right_zero else (1, 1) if left_true and right_true else (0, 1)
                else:
                    result = (1, 1) if left_true or right_true else (0, 0) if left_zero and right_zero else (0, 1)
    return coerce_interval(result, typed(node), layout)


def comparison_reference(node, layout):
    """Return a declaration only through globally value-preserving conversions.

In particular `(unsigned char)n <= 4` cannot constrain the original n. Mixed
signed/unsigned comparisons are not inverted unless the cast preserves every
source value. This deliberately sacrifices precision rather than invent a guard.
"""
    for _ in range(64):
        kind, inner = node.get('kind'), children(node)
        if kind == 'DeclRefExpr':
            return node.get('referencedDecl', {}).get('id')
        if kind == 'ParenExpr' and len(inner) == 1:
            node = inner[0]
            continue
        if kind not in ('ImplicitCastExpr', 'CStyleCastExpr', 'CXXStaticCastExpr') or len(inner) != 1:
            return None
        if node.get('castKind') not in ('IntegralCast', 'NoOp', 'LValueToRValue'):
            return None
        source, target = type_interval(typed(inner[0]), layout), type_interval(typed(node), layout)
        if source is None or target is None or not target[0] <= source[0] <= source[1] <= target[1]:
            return None
        node = inner[0]
    return None
