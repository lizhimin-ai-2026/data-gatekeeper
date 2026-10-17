#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据隔离守门员 · 统一数据入口包装层 (gateway_wrapper)

挂真实入口的「云函数包装模板 / 装饰器」。任何数据库访问先经过守门员，
白名单之外一律拒（默认拒绝）。拦截点前置：请求未落地前拦截，数据不返回。

宿主（你的宿主程序 / 云函数 / 任意宿主程序）直接引用：
  from gateway_wrapper import DataEntryGateway, gatekeep

只拦不删：本模块不触碰、不修改、不删除任何库数据。
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


class DataEntryGateway:
    """统一数据入口：拦截点前置的网关守卫。"""

    def __init__(self, rules_path=None):
        import gatekeeper as gk
        self.gk = gk
        if rules_path:
            # 允许宿主指定规则库位置（不影响 gatekeeper 内部默认路径时通常不用）
            self.gk.RULES_OVERRIDE = rules_path

    def handle(self, request):
        """
        处理一次访问请求。
        request 字段：caller(或 source) / token / function / operation / table(可选)。
        返回决策字典：{result, severity, rule_id, note, allowed, decision}
        """
        gk = self.gk
        caller = request.get("caller") or request.get("source") or ""
        token = request.get("token") or ""
        function = request.get("function") or ""
        operation = request.get("operation") or ""
        table = request.get("table")
        rules = gk.load_rules()
        result, severity, rule_id, note, hd = gk.decide(
            rules, caller, token, function, operation, table
        )
        event = gk.build_event(caller, function, operation, table, result, severity, rule_id, note, hd)
        gk.append_local_event(event)
        gk.push_to_audit(event)
        return {
            "result": result,
            "severity": severity,
            "rule_id": rule_id,
            "note": note,
            "allowed": result == "ALLOW",
            "decision": "BLOCK" if result != "ALLOW" else "PASS",
        }


def gatekeep(function_name, operation="SELECT", table=None):
    """
    装饰器：包裹一个数据库访问函数，调用前先过守门员。
    请求上下文从第一个参数 request_context(字典) 取 caller/token。
    """
    def decorator(fn):
        def wrapper(request_context, *args, **kwargs):
            gw = DataEntryGateway()
            decision = gw.handle({
                **request_context,
                "function": function_name,
                "operation": operation,
                "table": table,
            })
            if not decision["allowed"]:
                raise PermissionError(f"数据访问被守门员拦截: {decision['note']}")
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator


# --------------------------------------------------------------------------
# 云函数入口示例（AWS Lambda / 任意 FaaS 形态）
# 宿主把本文件作为 handler 挂载即可；请求体须含 caller/token/function/operation/table
# --------------------------------------------------------------------------
def handler(event, context=None):
    """云函数包装层入口。event 即请求体字典。"""
    gw = DataEntryGateway()
    return gw.handle(event)


if __name__ == "__main__":
    # 简单自测：无 token 的越权访问应被拦截
    gw = DataEntryGateway()
    print(gw.handle({"caller": "rogue", "token": "", "function": "evil", "operation": "SELECT", "table": "x"}))
    tok = gw.gk.issue_token(gw.gk.load_rules(), "demo", 3600)
    print(gw.handle({"caller": "demo", "token": tok, "function": "syncKnowledge", "operation": "SELECT", "table": "knowledge_base"}))
