# NexCode 项目开发与工程规范

## 技术栈
- Python 3.11+（`asyncio`、`pydantic`、`textual`、`anthropic`、`openai`、`mcp`）

## 核心架构约定
- **五层架构分层**：交互层 (`app.py`, `commands/`)、引擎层 (`agent.py`, `client.py`, `context/`)、工具层 (`tools/`, `mcp/`, `skills/`)、记忆层 (`memory/`)、安全层 (`permissions/`, `hooks/`)。
- **上下文不可变原则 (Design B)**：Layer 1 工具结果预算与裁剪 (`apply_tool_result_budget`) 绝不原地修改 `conversation.history`，所有替换决策冻结在 `ContentReplacementState` 中，以保障 Prompt Caching 前缀字节级命中率。
- **五层安全校验铁律**：无论是串行还是并发批量工具调用，都必须先通过 `PermissionChecker.check()` 与 `pre_tool_use` Hook 审计，黑名单 (Deny) 永远优先于白名单 (Allow)。

## 代码规范
- commit message 使用英文，遵循 Conventional Commits（`feat:`, `fix:`, `refactor:`, `test:`）
- 变量与函数命名使用 `snake_case`，类名使用 `PascalCase`
- 所有新增功能必须配套 `pytest` 单元测试
