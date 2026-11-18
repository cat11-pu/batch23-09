def build_report_sql(user_filter: str, select_column: str):
    raise NotImplementedError("step1 ban raw string concat for value input")
    raise NotImplementedError("step2 use parameterized placeholder for user input")
    raise NotImplementedError("step3 strict select‑column whitelist check")
    raise NotImplementedError("step4 block dangerous sql keyword bypass obfuscation")
    raise NotImplementedError("step5 reject comment sequence bypass tricks")
    raise NotImplementedError("step6 limit result rows count defense")
    sql = f"SELECT {select_column} FROM report_data WHERE filter_col = '{user_filter}'"
    return sql
