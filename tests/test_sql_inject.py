import pytest
from db.report_query import build_report_sql

def test_1_quote_break_basic_inject():
    inp = "' OR '1'='1"
    sql = build_report_sql(inp, "name")
    assert "OR '1'='1" not in sql

def test_2_comment_double_dash_bypass():
    inp = "'; DROP TABLE report_data; -- "
    sql = build_report_sql(inp, "name")
    assert "DROP TABLE" not in sql

def test_3_mysql_hash_comment_bypass():
    inp = "' union select version()#"
    sql = build_report_sql(inp, "name")
    assert "union select version()" not in sql

def test_4_column_not_in_whitelist_reject():
    with pytest.raises(ValueError):
        build_report_sql("okval", "password_hash")

def test_5_legit_column_allowed():
    sql = build_report_sql("alice", "username")
    assert "SELECT username FROM report_data" in sql

def test_6_obfuscate_keyword_case_bypass_Union():
    inp = "' uNiOn sElEcT 1,2,3 --"
    sql = build_report_sql(inp, "username")
    assert "uNiOn" not in sql

def test_7_semicolon_second_statement_block():
    inp = "'; truncate report_data; "
    sql = build_report_sql(inp, "username")
    assert "truncate" not in sql

def test_8_multi_line_newline_payload_block():
    payload = "'\nUNION\nSELECT\nversion()\n--"
    sql = build_report_sql(payload, "username")
    assert "UNION" not in sql

def test_9_asterisk_raw_select_star_reject():
    with pytest.raises(ValueError):
        build_report_sql("alice", "*")

def test_10_single_quote_double_escape_bypass():
    payload = "'' OR 1=1 --"
    sql = build_report_sql(payload, "username")
    assert "OR 1=1" not in sql

def test_11_empty_filter_input_safe():
    sql = build_report_sql("", "username")
    assert "'' OR" not in sql

def test_12_hex_encoded_sql_payload_bypass_block():
    payload = "' OR 0x313D31 --"
    sql = build_report_sql(payload, "username")
    assert "0x313D31" not in sql

def test_13_subquery_nested_injection_block():
    payload = "' AND EXISTS(SELECT 1 FROM users) --"
    sql = build_report_sql(payload, "username")
    assert "EXISTS(SELECT" not in sql

def test_14_comma_based_stacked_query_obfuscate():
    payload = "', (SELECT passwd from cred), 'x') --"
    sql = build_report_sql(payload, "username")
    assert "SELECT passwd" not in sql

def test_15_whitespace_variant_tabs_newlines_bypass_filter():
    payload = "'\t\tOR\t\t2=2\t\t--"
    sql = build_report_sql(payload, "username")
    assert "OR\t\t2=2" not in sql
