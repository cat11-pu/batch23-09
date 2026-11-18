from urllib.parse import quote

import pytest

from db.report_query import (
    ALLOWED_COLUMNS,
    MAX_FILTER_LENGTH,
    build_report_query,
    build_report_sql,
    build_safe_report_query,
    validate_filter_value,
)


ATTACK_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE report_data; -- ",
    "' union select version()#",
    "' uNiOn sElEcT 1,2,3 --",
    "'; truncate report_data; ",
    "'\nUNION\nSELECT\nversion()\n--",
    "'' OR 1=1 --",
    "' OR 0x313D31 --",
    "' AND EXISTS(SELECT 1 FROM users) --",
    "', (SELECT passwd from cred), 'x') --",
    "'\t\tOR\t\t2=2\t\t--",
    "＇　ｕｎｉｏｎ　ｓｅｌｅｃｔ　１",
    "' ;/**/SeLeCt/**/user ; #",
    "abc\x00def",
]


@pytest.mark.parametrize("payload", ATTACK_PAYLOADS)
def test_validator_rejects_obfuscated_payloads(payload):
    with pytest.raises(ValueError):
        validate_filter_value(payload)


@pytest.mark.parametrize("payload", ATTACK_PAYLOADS)
def test_safe_builder_rejects_obfuscated_payloads(payload):
    with pytest.raises(ValueError):
        build_safe_report_query(payload, "username")


@pytest.mark.parametrize("layers", [1, 2, 3])
def test_percent_encoded_payloads_are_decoded_and_rejected(layers):
    payload = "' UNION SELECT password_hash FROM users --"
    encoded = payload
    for _ in range(layers):
        encoded = quote(encoded)
    with pytest.raises(ValueError):
        validate_filter_value(encoded)


def test_comment_variants_all_rejected():
    for marker in ["--", "/*", "*/", "#"]:
        with pytest.raises(ValueError):
            validate_filter_value(f"value {marker} tail")


def test_stacked_semicolon_rejected():
    with pytest.raises(ValueError):
        validate_filter_value("ok; DROP TABLE report_data")


def test_overlong_input_rejected():
    with pytest.raises(ValueError):
        validate_filter_value("a" * (MAX_FILTER_LENGTH + 1))


def test_hex_and_tautology_rejected():
    with pytest.raises(ValueError):
        validate_filter_value("' OR 0x313D31 --")
    with pytest.raises(ValueError):
        validate_filter_value("x OR 1=1")


@pytest.mark.parametrize("bad_column", ["*", "password_hash", "NAME", "id --", "1=1", ""])
def test_select_column_whitelist_strict(bad_column):
    with pytest.raises(ValueError):
        build_report_sql("alice", bad_column)


def test_every_whitelisted_column_builds():
    for column in sorted(ALLOWED_COLUMNS):
        sql = build_report_sql("alice", column)
        assert f"SELECT {column} FROM report_data" in sql


@pytest.mark.parametrize("bad_order", ["password_hash", "1; DROP TABLE x", "(SELECT 1)"])
def test_order_by_whitelist_strict(bad_order):
    with pytest.raises(ValueError):
        build_report_sql("alice", "username", order_by=bad_order)


def test_order_direction_whitelist():
    sql = build_report_sql("alice", "username", order_by="name", order_dir="desc")
    assert "ORDER BY name DESC" in sql
    with pytest.raises(ValueError):
        build_report_sql("alice", "username", order_by="name", order_dir="SIDEWAYS")


@pytest.mark.parametrize("bad_limit", [0, 1001, "100", 1.5, True])
def test_limit_must_be_bounded_int(bad_limit):
    with pytest.raises(ValueError):
        build_report_sql("alice", "username", limit=bad_limit)


def test_user_value_never_enters_sql_text():
    payload = "'; DROP TABLE report_data; --"
    sql, params = build_report_query(payload, "username")
    assert payload not in sql
    assert "'" not in sql
    assert sql == (
        "SELECT username FROM report_data WHERE filter_col = ? LIMIT 100"
    )
    assert params == (payload,)


def test_legitimate_query_remains_usable():
    sql, params = build_safe_report_query(
        "alice", "username", order_by="id", order_dir="ASC", limit=10
    )
    assert params == ("alice",)
    assert sql == (
        "SELECT username FROM report_data "
        "WHERE filter_col = ? ORDER BY id ASC LIMIT 10"
    )


def test_benign_words_are_not_false_positives():
    assert validate_filter_value("color coordination report") is True
    assert validate_filter_value("") is True
