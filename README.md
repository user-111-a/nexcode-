# NexCode — 轻量级终端 AI 编程助手 (CLI Coding Agent)

基于 **ReAct** 与 **Plan Mode** 双模式驱动 LLM 自主完成复杂软件工程任务的终端 AI 编程助手。采用 **交互、引擎、工具、记忆、安全** 五层架构设计，原生支持 Anthropic / OpenAI / OpenAI-Compatible 协议、MCP 工具动态扩展、Skill 技能包、跨会话自动记忆沉淀以及基于 Git Worktree 隔离的多 Agent 并行协作。

---

## 核心架构亮点

### 1. MCP 工具延迟加载 (Deferred Tool Loading)
- **按需暴露 Schema**：MCP 工具注册时默认标记 `should_defer = True`，初始请求只在 `<system-reminder>` 中同步工具名称和一行描述摘要，不传递参数 Schema。
- **动态检索激活**：模型按需调用 `ToolSearch`（支持 `select:<name>` 精确加载与关键词加权检索）动态解锁目标工具 Schema。
- **实测收益**：在 100 个企业级 MCP 工具场景下，首轮 Prompt 工具定义 Token 占用由 **22,199 tokens 降至 3,177 tokens（降低 85.7%）**。省下的是参数 Schema，名称和一行描述摘要仍然在，模型可以先判断要不要加载。

### 2. 两层渐进式上下文压缩引擎 (2-Layer Progressive Context Compression)
- **Layer 1（工具结果预算 + Design B 决策冻结 + AST/Traceback 语义化裁剪）**：
  - **大输出自动落盘**：单条超 50KB 或单轮累计超 200KB 的工具输出自动持久化至 `.nexcode/session/tool-results/`，仅向模型返回 2KB 预览与文件路径。
  - **Design B 替换状态冻结**：通过 `ContentReplacementState` 冻结历史替换决策，不原地篡改原始对话，保障 Anthropic / OpenAI Prompt Caching 前缀字节级一致。
  - **工具感知语义裁剪 (`smart_snip_tool_result`)**：对超过 10 轮的陈旧工具输出，若为代码文件则通过 Python `ast` 自动提取**类/函数签名与行号骨架（AST Skeleton）**（压缩率 **91.1%**，关键符号保留率 **100%**）；若为 `Bash` 终端输出则采用 **Head + Error Traceback + Tail** 三段式浓缩，确保异常报错栈绝不丢失。
- **Layer 2（Auto-Compact 摘要 + 双向 Tool Pair 对齐 + 写穿透恢复）**：
  - 基于 API 真实计费锚点 (`record_usage_anchor`) 触发自动压缩，保留近期尾部原文（`KEEP_RECENT_TOKENS`），仅对早期前缀生成 9 段式结构化摘要。
  - **双向调用配对对齐 (`_align_keep_start_to_tool_pair`)**：严格保证 `assistant(tool_use)` 与 `user(tool_result)` 成对保留，杜绝悬空半对导致 API 400 报错。
  - **写穿透工作状态恢复 (`RecoveryState`)**：实时追踪 `ReadFile`、`WriteFile`、`EditFile` 与激活的 `Skill` SOP，压缩后自动挂载最新磁盘代码快照与已修改文件清单，消除压缩后“修改未生效”的模型幻觉。

### 3. 五层纵深权限拦截安全模型 (5-Layer Permission & Security Model)
无论工具处于串行执行还是 `asyncio.gather` 并发批量执行，均强制经过五层安全门控（任意一层拒绝即终止操作）：
1. **Layer 0 — Plan Mode 严格只读隔离**：Plan 模式下仅允许只读探测工具与指定计划文件 (`.nexcode/plans/*.md`) 写入。
2. **Layer 1 — 高危命令与 `shlex` 复合词法审计 (`DangerousCommandDetector`)**：优先于所有白名单执行，基于正则与 `shlex` 词法分析拆解 `;`、`&&`、`||`、`|` 复合子命令，精准拦截 `rm -rf /`、`find -delete`、管道远程脚本执行等破坏性操作。
3. **Layer 2 — 路径沙箱与敏感资产保护 (`PathSandbox`)**：基于 `Path.resolve(strict=True)` 防御软链接逃逸（Symlink Escape）；对 `.env*`、`.ssh/`、`id_rsa` 等敏感凭证文件禁止直接覆写；同时提取 `Bash` 命令内的显式路径参数联动沙箱校验，封堵 `cat /etc/passwd` 等绕过路径。
4. **Layer 3 — 三级 YAML 规则引擎 (`RuleEngine`)**：支持 `user` -> `project` -> `local` 三级 `Tool(glob_pattern)` 细粒度规则匹配。
5. **Layer 4 & 5 — 词法级只读白名单 (`is_safe_command`) + 权限模式 + HITL 人工确认**：对 `sed -i`、`git branch -D`、`find -exec` 等含写副作用的参数变体严格剔除出自动放行白名单，基于 `asyncio.Future` 挂起等待人工审批，并支持 `ALLOW_ALWAYS` 动态规则落盘。

### 4. 跨会话自动记忆系统 (Auto-Memory & Selective Recall)
- 每隔固定轮次异步调用 LLM 复盘近期对话，自动提取**用户偏好、纠正反馈、项目知识、参考资料**四类长期记忆，分别持久化至用户级 (`~/.nexcode/memories.md`) 与项目级 (`.nexcode/memories.md`)，并支持带 YAML Frontmatter 的独立记忆文件按需相关性召回 (`recall.py`) 与过期新鲜度告警。

### 5. 多 Agent 并行协作与 Git Worktree 文件级隔离
- 支持 **SubAgent**（`Explore` / `Plan` / `Verification` / `Fork`）与 **Agent Team**（`Coordinator` + `Teammates`）。
- 每个并行子 Agent 分配独立的 **Git Worktree** 工作区与专属 `PathSandbox`，通过无子进程开销的 `.git` 文件解析 (`read_worktree_head_sha`) 实现毫秒级恢复，配合 `Mailbox` 消息队列与 `SharedTaskStore` 实现无冲突并行研发。

---

## 快速开始

### 安装依赖
```bash
pip install -e .
```

### 运行测试与量化基准评测
```bash
# 运行全部单元测试
pytest -q

# 运行核心指标量化基准评测
python benchmarks/run_benchmarks.py
```
