from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from nexcode.permissions.dangerous import DangerousCommandDetector, is_safe_command
from nexcode.permissions.modes import DecisionEffect, PermissionMode, mode_decide
from nexcode.permissions.rules import RuleEngine, extract_content
from nexcode.permissions.sandbox import PathSandbox
from nexcode.tools.base import Tool

_PLAN_MODE_ALLOWED_TOOLS = frozenset({"Agent", "ToolSearch", "AskUserQuestion", "ExitPlanMode"})


@dataclass
class Decision:
    effect: DecisionEffect
    reason: str


class PermissionChecker:
    """五层纵深权限校验引擎：
    - Layer 0: Plan 模式严格只读与计划文件白名单校验
    - Layer 1: 高危命令与破坏性词法黑名单拦截（DangerousCommandDetector）
    - Layer 2: 路径沙箱与敏感资产保护（PathSandbox 文件边界 + 命令内路径审计）
    - Layer 3: 三级 YAML 规则引擎（user -> project -> local）细粒度匹配
    - Layer 4: 词法级只读安全命令放行（is_safe_command）与权限模式（PermissionMode）判定
    - Layer 5: 人工确认（HITL Future 异步挂起）
    """

    def __init__(
        self,
        detector: DangerousCommandDetector,
        sandbox: PathSandbox,
        rule_engine: RuleEngine,
        mode: PermissionMode = PermissionMode.DEFAULT,
    ) -> None:
        self.detector = detector
        self.sandbox = sandbox
        self.rule_engine = rule_engine
        self.mode = mode
        self.plan_file_path: str = ""

    def check(self, tool: Tool, arguments: dict[str, Any]) -> Decision:
        content = extract_content(tool.name, arguments)

        # Layer 0: Plan 模式例外放行
        if self.mode == PermissionMode.PLAN:
            if tool.name in _PLAN_MODE_ALLOWED_TOOLS:
                return Decision(effect="allow", reason="Plan mode: allowed tool")
            if tool.name in ("WriteFile", "EditFile") and content:
                if self._is_plan_file(content):
                    return Decision(effect="allow", reason="Plan mode: plan file write")

        # Layer 1: 危险命令黑名单与破坏性参数拦截（最高优先级 Deny，先于任何白名单）
        if tool.category == "command":
            hit, reason = self.detector.detect(content or "")
            if hit:
                return Decision(effect="deny", reason=f"危险命令拦截: {reason}")

        # Layer 2: 路径沙箱与敏感资产保护（覆盖文件类工具 + 命令内显式路径参数）
        if tool.category in ("read", "write") and content:
            ok, reason = self.sandbox.check(content, is_write=(tool.category == "write"))
            if not ok:
                return Decision(effect="deny", reason=f"路径沙箱拦截: {reason}")
        elif tool.category == "command" and content:
            ok, reason = self.sandbox.check_command_paths(content)
            if not ok:
                return Decision(effect="deny", reason=f"路径沙箱拦截: {reason}")

        # Layer 3: 规则引擎匹配（user -> project -> local）
        rule_result = self.rule_engine.evaluate(tool.name, content)
        if rule_result == "allow":
            return Decision(effect="allow", reason="权限规则放行")
        if rule_result == "deny":
            return Decision(effect="deny", reason="权限规则拒绝")

        # Layer 4a: 经过词法审计的纯只读安全命令（非 PLAN / 非 CUSTOM 模式下自动放行）
        if (
            tool.category == "command"
            and self.mode not in (PermissionMode.PLAN, PermissionMode.CUSTOM)
            and is_safe_command(content or "")
        ):
            return Decision(effect="allow", reason="Safe read-only command")

        # Layer 4b: 权限模式兜底判定
        effect = mode_decide(self.mode, tool.category)
        if effect == "allow":
            return Decision(effect="allow", reason=f"权限模式 {self.mode.value} 放行")
        if effect == "deny":
            return Decision(effect="deny", reason=f"权限模式 {self.mode.value} 拒绝")

        # Layer 5: 触发人工确认（HITL）
        return Decision(effect="ask", reason="需要用户确认")

    def _is_plan_file(self, target_path: str) -> bool:
        if not self.plan_file_path or not target_path:
            return ".nexcode/plans/" in target_path.replace("\\", "/")
        try:
            abs_target = os.path.abspath(target_path)
            abs_plan = os.path.abspath(self.plan_file_path)
            if abs_target == abs_plan:
                return True
        except Exception:
            pass
        if os.path.basename(target_path) == os.path.basename(self.plan_file_path):
            return True
        return ".nexcode/plans/" in target_path.replace("\\", "/")
