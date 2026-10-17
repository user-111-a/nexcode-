from __future__ import annotations

from nexcode.commands.registry import Command, CommandContext, CommandType


async def handle_do(ctx: CommandContext) -> None:
    ctx.ui.set_plan_mode(False)
    ctx.ui.add_system_message("已退出 Plan 模式 — 恢复正常执行模式")
    if ctx.args:
        ctx.ui.send_user_message(ctx.args)


DO_COMMAND = Command(
    name="do",
    aliases=["d"],
    description="退出 Plan 模式并执行任务",
    usage="/do [任务描述]",
    type=CommandType.LOCAL_UI,
    handler=handle_do,
)
