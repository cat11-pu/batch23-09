# GSB Bugfix Task
## 题面
动态报表查询接口存在注入漏洞：直接拼接用户输入到SQL语句、未使用参数化查询、仅简单过滤关键字、可绕过过滤注释、未限制查询字段；db/report_query.py 是核心，tests/test_sql_inject.py 15个红。要修的是：全部改为参数化查询、移除字符串拼接、字段白名单校验、禁用危险SQL关键字、限制查询列。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：无外部依赖
