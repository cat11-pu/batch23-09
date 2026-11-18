"""Hardened dynamic report query builder.

Security model
--------------
* User filter values are never concatenated into SQL text. They are always
  bound through a parameter placeholder (``?``) and returned separately in a
  params tuple, so quotes, comments, hex literals and stacked statements
  cannot alter the statement structure.
* Statement identifiers (the selected column and the optional sort field) are
  resolved against fixed whitelists; anything else raises ``ValueError``.
* ``validate_report_input`` / ``build_safe_report_query`` perform explicit
  input hygiene and raise a clear ``ValueError`` for dangerous statements,
  comment variants, percent-encoding layers, whitespace/case obfuscation,
  hex literals, tautologies and over-long input.
* Result rows are always capped by a validated integer ``LIMIT``.
"""

import re
import unicodedata
from urllib.parse import unquote

__all__ = [
    "ALLOWED_COLUMNS",
    "ALLOWED_ORDER_COLUMNS",
    "MAX_FILTER_LENGTH",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "build_report_sql",
    "build_report_query",
    "build_safe_report_query",
    "validate_report_input",
    "validate_filter_value",
]

# Whitelist of columns that may be projected. ``password_hash`` and ``*`` are
# intentionally absent.
ALLOWED_COLUMNS = frozenset(
    {
        "id",
        "username",
        "name",
        "email",
        "department",
        "status",
        "category",
        "amount",
        "report_date",
        "created_at",
    }
)

# Sorting is restricted to an even smaller, index-friendly subset.
ALLOWED_ORDER_COLUMNS = frozenset(
    {
        "id",
        "username",
        "name",
        "amount",
        "report_date",
        "created_at",
    }
)
ALLOWED_ORDER_DIRECTIONS = frozenset({"ASC", "DESC"})

MAX_FILTER_LENGTH = 1000
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000

_DANGEROUS_KEYWORDS = (
    "information_schema",
    "load_file",
    "benchmark",
    "truncate",
    "shutdown",
    "execute",
    "replace",
    "revoke",
    "outfile",
    "dumpfile",
    "select",
    "insert",
    "update",
    "delete",
    "create",
    "alter",
    "union",
    "sleep",
    "grant",
    "exists",
    "rename",
    "having",
    "version",
    "exec",
    "drop",
    "load",
)
_KEYWORD_RE = re.compile(r"\b(?:" + "|".join(_DANGEROUS_KEYWORDS) + r")\b")
_HEX_LITERAL_RE = re.compile(r"0x[0-9a-f]+")
_TAUTOLOGY_RE = re.compile(
    r"\b(?:or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?"
)
_WHITESPACE_RE = re.compile(r"\s+")
_COMMENT_MARKERS = ("--", "/*", "*/", "#")
_DECODE_LAYERS = 3


def _decoded_layers(value):
    """Yield the raw value plus each percent-decoding layer (multi-encoding)."""
    current = value
    yield current
    for _ in range(_DECODE_LAYERS):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
        yield current


def _normalize_for_scan(value):
    """NFKC-fold full-width obfuscation, lowercase and collapse whitespace."""
    normalized = unicodedata.normalize("NFKC", value).lower()
    return _WHITESPACE_RE.sub(" ", normalized)


def validate_filter_value(user_filter):
    """Reject dangerous/obfuscated filter values with a clear ``ValueError``.

    Scans the raw value and every percent-decoding layer, so URL-encoded and
    multi-encoded payloads are inspected after decoding. Whitespace (tabs,
    newlines, CR, vertical tabs) is collapsed and the text is NFKC-folded and
    lower-cased before keyword matching, defeating case and spacing variants.
    """
    if not isinstance(user_filter, str):
        raise ValueError("filter value must be a string")
    if len(user_filter) > MAX_FILTER_LENGTH:
        raise ValueError(
            f"filter value exceeds maximum length of {MAX_FILTER_LENGTH} characters"
        )
    if "\x00" in user_filter:
        raise ValueError("filter value contains a forbidden null byte")

    for layer in _decoded_layers(user_filter):
        for marker in _COMMENT_MARKERS:
            if marker in layer:
                raise ValueError(
                    f"filter value contains forbidden SQL comment marker {marker!r}"
                )
        if ";" in layer:
            raise ValueError(
                "filter value contains forbidden stacked-query separator ';'"
            )

        scan = _normalize_for_scan(layer)
        keyword_match = _KEYWORD_RE.search(scan)
        if keyword_match:
            raise ValueError(
                "filter value contains forbidden SQL keyword "
                f"{keyword_match.group(0)!r}"
            )
        hex_match = _HEX_LITERAL_RE.search(scan)
        if hex_match:
            raise ValueError(
                "filter value contains forbidden hexadecimal literal "
                f"{hex_match.group(0)!r}"
            )
        if _TAUTOLOGY_RE.search(scan):
            raise ValueError(
                "filter value contains forbidden boolean tautology expression"
            )
    return True


def resolve_select_column(select_column):
    """Return the column only when it is an exact whitelist member."""
    if not isinstance(select_column, str):
        raise ValueError("select column must be a string identifier from the whitelist")
    if select_column not in ALLOWED_COLUMNS:
        raise ValueError(
            f"select column {select_column!r} is not allowed; "
            f"allowed columns: {sorted(ALLOWED_COLUMNS)}"
        )
    return select_column


def _build_order_clause(order_by, order_dir):
    if order_by is None:
        return ""
    if not isinstance(order_by, str) or order_by not in ALLOWED_ORDER_COLUMNS:
        raise ValueError(
            f"sort field {order_by!r} is not allowed; "
            f"allowed sort fields: {sorted(ALLOWED_ORDER_COLUMNS)}"
        )
    if not isinstance(order_dir, str):
        raise ValueError("sort direction must be 'ASC' or 'DESC'")
    direction = order_dir.upper()
    if direction not in ALLOWED_ORDER_DIRECTIONS:
        raise ValueError("sort direction must be 'ASC' or 'DESC'")
    return f"ORDER BY {order_by} {direction}"


def _coerce_limit(limit):
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError(f"limit must be an integer between 1 and {MAX_LIMIT}")
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an integer between 1 and {MAX_LIMIT}")
    return limit


def validate_report_input(user_filter, select_column, order_by=None, order_dir="ASC"):
    """Full explicit validation entry point; raises ``ValueError`` on any issue."""
    validate_filter_value(user_filter)
    resolve_select_column(select_column)
    _build_order_clause(order_by, order_dir)
    return True


def build_report_sql(
    user_filter,
    select_column,
    order_by=None,
    order_dir="ASC",
    limit=DEFAULT_LIMIT,
):
    """Build safe SQL text.

    The filter value is represented by a ``?`` placeholder and is never
    embedded in the statement. The projected column and optional sort field
    are whitelisted identifiers, and ``limit`` is a bounded integer.
    """
    column = resolve_select_column(select_column)
    order_clause = _build_order_clause(order_by, order_dir)
    safe_limit = _coerce_limit(limit)

    sql_parts = [f"SELECT {column} FROM report_data WHERE filter_col = ?"]
    if order_clause:
        sql_parts.append(order_clause)
    sql_parts.append(f"LIMIT {safe_limit}")
    return " ".join(sql_parts)


def build_report_query(
    user_filter,
    select_column,
    order_by=None,
    order_dir="ASC",
    limit=DEFAULT_LIMIT,
):
    """Return ``(sql, params)`` ready for a parameterized DBAPI execute."""
    sql = build_report_sql(user_filter, select_column, order_by, order_dir, limit)
    return sql, (user_filter,)


def build_safe_report_query(
    user_filter,
    select_column,
    order_by=None,
    order_dir="ASC",
    limit=DEFAULT_LIMIT,
):
    """Validate inputs explicitly, then return a parameterized query.

    Raises ``ValueError`` with a clear message for dangerous statements,
    comment/encoding obfuscation, over-long values or non-whitelisted
    identifiers.
    """
    validate_report_input(user_filter, select_column, order_by, order_dir)
    return build_report_query(
        user_filter, select_column, order_by, order_dir, limit
    )
