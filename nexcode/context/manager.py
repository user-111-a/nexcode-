from __future__ import annotations

import ast
import json
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from nexcode.conversation import (
    ConversationManager,
    Message,
    ToolResultBlock,
    estimate_tokens,
)
from nexcode.serialization import build_messages

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

SINGLE_RESULT_CHAR_LIMIT = 50_000
AGGREGATE_CHAR_LIMIT = 200_000
PREVIEW_CHARS = 2_000

KEEP_RECENT_TURNS = 10
OLD_RESULT_SNIP_CHARS = 2_000
SNIPPED_TAG = "<snipped>"

SUMMARY_OUTPUT_RESERVE = 20_000
AUTO_COMPACT_SAFETY_MARGIN = 13_000
MANUAL_COMPACT_SAFETY_MARGIN = 3_000

# Layer 2 "保留近期原文"窗口。压缩时，尾部消息按 token 累计不超过
# KEEP_RECENT_TOKENS、或消息数不少于 MIN_KEEP_MESSAGES（取先满足的条件保底）保留原文，
# 不纳入摘要。累计超过 KEEP_MAX_TOKENS 时停止，防止单条超大消息吞掉整个窗口。
KEEP_RECENT_TOKENS = 10_000
MIN_KEEP_MESSAGES = 5
KEEP_MAX_TOKENS = 40_000

# 前缀 token 数低于此阈值时不值得做摘要——摘要往返的开销比回收的空间还大，
# 退化为不压缩、保留原始历史。
MIN_SUMMARIZE_PREFIX_TOKENS = 2_000

PERSISTED_TAG = "<persisted-output>"

SESSION_SUBDIR = ".nexcode/session/tool-results"


# ---------------------------------------------------------------------------
# 事件
# ---------------------------------------------------------------------------


@dataclass
class CompactBoundary:
    """Layer 2 压缩的结构化结果，上交给 session 层处理。"""

    summary: str
    keep: list[Message]


@dataclass
class CompactEvent:
    before_tokens: int
    boundary: CompactBoundary | None = None


# ---------------------------------------------------------------------------
# 内容替换状态 — Design B（决策冻结，不做原地修改）
# ---------------------------------------------------------------------------

@dataclass
class ContentReplacementState:
    seen_ids: set[str] = field(default_factory=set)
    replacements: dict[str, str] = field(default_factory=dict)
    tool_names: dict[str, str] = field(default_factory=dict)


@dataclass
class ContentReplacementRecord:
    tool_use_id: str
    replacement: str
    kind: str = "tool-result"


def create_replacement_state() -> ContentReplacementState:
    return ContentReplacementState()


def clone_replacement_state(src: ContentReplacementState) -> ContentReplacementState:
    return ContentReplacementState(
        seen_ids=set(src.seen_ids),
        replacements=dict(src.replacements),
        tool_names=dict(src.tool_names),
    )


REPLACEMENT_RECORDS_FILENAME = "replacement_records.jsonl"


def append_replacement_records(
    session_dir: Path, records: list[ContentReplacementRecord]
) -> None:
    if not records:
        return
    path = session_dir / REPLACEMENT_RECORDS_FILENAME
    with path.open("a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps({
                "kind": r.kind,
                "tool_use_id": r.tool_use_id,
                "replacement": r.replacement,
            }, ensure_ascii=False) + "\n")


def load_replacement_records(session_dir: Path) -> list[ContentReplacementRecord]:
    path = session_dir / REPLACEMENT_RECORDS_FILENAME
    if not path.exists():
        return []
    out: list[ContentReplacementRecord] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            out.append(ContentReplacementRecord(
                kind=obj.get("kind", "tool-result"),
                tool_use_id=obj["tool_use_id"],
                replacement=obj["replacement"],
            ))
    return out


def reconstruct_replacement_state(
    messages: list[Message],
    records: list[ContentReplacementRecord],
    inherited_replacements: Mapping[str, str] | None = None,
) -> ContentReplacementState:
    state = create_replacement_state()
    candidate_ids: set[str] = set()
    for msg in messages:
        for tu in msg.tool_uses:
            state.tool_names[tu.tool_use_id] = tu.tool_name
        for tr in msg.tool_results:
            candidate_ids.add(tr.tool_use_id)
    state.seen_ids.update(candidate_ids)
    for r in records:
        if r.kind == "tool-result" and r.tool_use_id in candidate_ids:
            state.replacements[r.tool_use_id] = r.replacement
    if inherited_replacements:
        for tool_use_id, replacement in inherited_replacements.items():
            if tool_use_id in candidate_ids and tool_use_id not in state.replacements:
                state.replacements[tool_use_id] = replacement
    return state


# ---------------------------------------------------------------------------
# Session 目录管理
# ---------------------------------------------------------------------------

def ensure_session_dir(work_dir: str) -> Path:
    session_dir = Path(work_dir) / SESSION_SUBDIR
    session_dir.mkdir(parents=True, exist_ok=True)
    return session_dir


def cleanup_tool_results(session_dir: Path) -> None:
    if session_dir.exists():
        shutil.rmtree(session_dir)
        session_dir.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Layer 1：大型工具结果落盘 & 工具感知的 AST/Traceback 语义化裁剪
# ---------------------------------------------------------------------------

def persist_tool_result(tool_use_id: str, content: str, session_dir: Path) -> Path:
    file_path = session_dir / f"{tool_use_id}.txt"
    try:
        fd = os.open(str(file_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    except FileExistsError:
        pass
    return file_path


def make_persisted_preview(content: str, file_path: Path) -> str:
    size_kb = len(content.encode("utf-8")) // 1024
    preview = content[:PREVIEW_CHARS]
    return (
        f"{PERSISTED_TAG}\n"
        f"输出太大（{size_kb}KB），完整内容已保存到：\n"
        f"{file_path}\n"
        f"\n"
        f"预览（前 2KB）：\n"
        f"{preview}\n"
        f"</persisted-output>"
    )


_LINE_NUM_PREFIX_RE = re.compile(r"^\s*(\d+)[\t|](.*)$")
_ERROR_LINE_RE = re.compile(
    r"(Traceback \(most recent call last\)|^\s*File \".*\", line \d+|"
    r"\b\w*Error:|Exception:|FAILED\b|ERROR\b|fatal:|panic:)",
    re.IGNORECASE,
)
_SYMBOL_DEF_RE = re.compile(
    r"^\s*(?:async\s+def|def|class|function|export\s+(?:async\s+)?function|"
    r"interface|type|struct|impl|func)\s+\w+"
)


def _strip_line_numbers(text: str) -> tuple[str, list[int]]:
    """剥离 ReadFile 输出中的行号前缀（如 '     1\\tcode'），返回纯源码与原始行号列表。"""
    raw_lines = text.splitlines()
    clean_lines: list[str] = []
    line_nums: list[int] = []
    matched_count = 0
    for idx, line in enumerate(raw_lines):
        m = _LINE_NUM_PREFIX_RE.match(line)
        if m:
            matched_count += 1
            line_nums.append(int(m.group(1)))
            clean_lines.append(m.group(2))
        else:
            line_nums.append(idx + 1)
            clean_lines.append(line)
    if matched_count >= max(1, len(raw_lines) // 2):
        return "\n".join(clean_lines), line_nums
    return text, list(range(1, len(raw_lines) + 1))


def _format_ast_args(args: ast.arguments) -> str:
    names = [a.arg for a in args.args]
    if args.vararg:
        names.append(f"*{args.vararg.arg}")
    if args.kwarg:
        names.append(f"**{args.kwarg.arg}")
    if len(names) > 5:
        return ", ".join(names[:4]) + ", ..."
    return ", ".join(names)


def _extract_python_ast_skeleton(content: str, max_items: int = 25) -> list[str]:
    """尝试用 Python 标准库 ast 解析源码并提取类与函数签名骨架。"""
    clean_src, line_map = _strip_line_numbers(content)
    try:
        tree = ast.parse(clean_src)
    except SyntaxError:
        return []

    def _real_line(lineno: int) -> int:
        if 1 <= lineno <= len(line_map):
            return line_map[lineno - 1]
        return lineno

    skeleton: list[str] = []
    for node in tree.body:
        if len(skeleton) >= max_items:
            skeleton.append("  ... (更多符号已省略)")
            break
        if isinstance(node, ast.ClassDef):
            start_l = _real_line(node.lineno)
            end_l = _real_line(getattr(node, "end_lineno", node.lineno) or node.lineno)
            bases = [ast.unparse(b) for b in node.bases] if hasattr(ast, "unparse") else []
            base_str = f"({', '.join(bases)})" if bases else ""
            skeleton.append(f"L{start_l}-L{end_l}: class {node.name}{base_str}:")
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    m_start = _real_line(item.lineno)
                    prefix = "async def" if isinstance(item, ast.AsyncFunctionDef) else "def"
                    sig = _format_ast_args(item.args)
                    skeleton.append(f"  L{m_start}: {prefix} {item.name}({sig})")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start_l = _real_line(node.lineno)
            end_l = _real_line(getattr(node, "end_lineno", node.lineno) or node.lineno)
            prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            sig = _format_ast_args(node.args)
            skeleton.append(f"L{start_l}-L{end_l}: {prefix} {node.name}({sig})")
    return skeleton


def smart_snip_tool_result(tool_name: str, content: str) -> str:
    """工具感知的语义化裁剪（Layer 1 Pass 3）：
    - ReadFile / WriteFile / EditFile：优先用 Python AST 提取类/函数签名与行号骨架；
      非 Python 文件则提取正则符号定义行 + 首尾摘要。
    - Bash：采用 Head + Error Traceback 关键报错行 + Tail 三段式浓缩，确保异常栈绝不丢失。
    - 其它工具：保留首尾关键上下文。
    """
    orig_len = len(content)
    lines = content.splitlines()

    if tool_name in ("ReadFile", "WriteFile", "EditFile") or _LINE_NUM_PREFIX_RE.match(lines[0] if lines else ""):
        ast_skeleton = _extract_python_ast_skeleton(content)
        if ast_skeleton:
            head_preview = "\n".join(lines[:3])
            body = "\n".join(ast_skeleton)
            return (
                f"{SNIPPED_TAG}\n"
                f"(旧代码结果已执行 AST 语义骨架裁剪，原始长度 {orig_len} 字符 / {len(lines)} 行)\n"
                f"[文件头部]\n{head_preview}\n"
                f"[AST 符号骨架 (行号 + 签名)]\n{body}\n"
                f"… (snipped — 如需查看具体实现细节请按行号调用 ReadFile)"
            )

        # 非 Python 代码降级：提取符号定义行 + 头尾预览
        regex_defs: list[str] = []
        for idx, line in enumerate(lines):
            m = _LINE_NUM_PREFIX_RE.match(line)
            lineno = m.group(1) if m else str(idx + 1)
            code_part = m.group(2) if m else line
            if _SYMBOL_DEF_RE.match(code_part):
                regex_defs.append(f"L{lineno}: {code_part.strip()[:100]}")
                if len(regex_defs) >= 20:
                    break
        if regex_defs:
            defs_block = "\n".join(regex_defs)
            return (
                f"{SNIPPED_TAG}\n"
                f"(旧文件结果已裁剪，原始长度 {orig_len} 字符)\n"
                f"[符号结构骨架]\n{defs_block}\n"
                f"… (snipped)"
            )

    if tool_name == "Bash" or content.startswith(("STDOUT:", "STDERR:")):
        head_lines = lines[:5]
        tail_lines = lines[-15:] if len(lines) > 5 else []
        middle_lines = lines[5:-15] if len(lines) > 20 else []
        error_highlights = [
            line for line in middle_lines if _ERROR_LINE_RE.search(line)
        ][:15]

        sections = ["\n".join(head_lines)]
        if error_highlights:
            sections.append("[关键异常与错误摘要]\n" + "\n".join(error_highlights))
        if tail_lines:
            sections.append("[尾部输出]\n" + "\n".join(tail_lines))
        merged = "\n...\n".join(s for s in sections if s)
        return (
            f"{SNIPPED_TAG}\n"
            f"(旧命令输出已执行首尾+异常栈保留裁剪，原始长度 {orig_len} 字符)\n"
            f"{merged}\n"
            f"… (snipped)"
        )

    # 默认首尾保留裁剪
    head_part = content[:150]
    tail_part = content[-150:] if len(content) > 300 else ""
    preview = f"{head_part}\n...\n{tail_part}" if tail_part else content[:200]
    return (
        f"{SNIPPED_TAG}\n"
        f"(旧结果已裁剪，原始长度 {orig_len} 字符)\n"
        f"{preview}\n"
        f"… (snipped)"
    )


def _count_turns(messages: list[Message]) -> int:
    count = 0
    for m in messages:
        if m.role == "assistant" and not m.tool_uses:
            count += 1
    return count


def _copy_message_with_results(
    msg: Message, new_tool_results: list[ToolResultBlock]
) -> Message:
    return Message(
        role=msg.role,
        content=msg.content,
        tool_uses=list(msg.tool_uses),
        tool_results=new_tool_results,
        thinking_blocks=list(msg.thinking_blocks),
    )


def _snip_stale_messages(
    history: list[Message],
    tool_names: Mapping[str, str] | None = None,
) -> list[Message]:
    total_turns = _count_turns(history)
    if total_turns <= KEEP_RECENT_TURNS:
        return history

    name_map: dict[str, str] = dict(tool_names) if tool_names else {}
    for msg in history:
        for tu in msg.tool_uses:
            name_map.setdefault(tu.tool_use_id, tu.tool_name)

    out: list[Message] = []
    turns_seen = 0
    old_boundary = total_turns - KEEP_RECENT_TURNS

    for msg in history:
        if msg.role == "assistant" and not msg.tool_uses:
            turns_seen += 1
        if turns_seen > old_boundary or not msg.tool_results:
            out.append(msg)
            continue

        new_results: list[ToolResultBlock] = []
        changed = False
        for tr in msg.tool_results:
            if (
                tr.content.startswith(SNIPPED_TAG)
                or tr.content.startswith(PERSISTED_TAG)
                or len(tr.content) <= OLD_RESULT_SNIP_CHARS
            ):
                new_results.append(tr)
                continue
            t_name = name_map.get(tr.tool_use_id, "")
            new_content = smart_snip_tool_result(t_name, tr.content)
            new_results.append(ToolResultBlock(
                tool_use_id=tr.tool_use_id,
                content=new_content,
                is_error=tr.is_error,
            ))
            changed = True

        out.append(_copy_message_with_results(msg, new_results) if changed else msg)

    return out


def apply_tool_result_budget(
    conversation: ConversationManager,
    session_dir: Path,
    state: ContentReplacementState,
) -> tuple[ConversationManager, list[ContentReplacementRecord]]:
    """Design B: 不 mutate 原 conversation，支持 Pass 1（单条落盘）+ Pass 2（聚合落盘）+ Pass 3（AST/异常感知裁剪）。"""
    new_records: list[ContentReplacementRecord] = []
    new_history: list[Message] = []

    for msg in conversation.history:
        for tu in msg.tool_uses:
            state.tool_names[tu.tool_use_id] = tu.tool_name

    for msg in conversation.history:
        if not msg.tool_results:
            new_history.append(msg)
            continue

        decisions: dict[str, str] = {}
        fresh: list[ToolResultBlock] = []

        for tr in msg.tool_results:
            if tr.tool_use_id in state.replacements:
                decisions[tr.tool_use_id] = state.replacements[tr.tool_use_id]
            elif tr.tool_use_id in state.seen_ids:
                decisions[tr.tool_use_id] = tr.content
            elif tr.content.startswith(PERSISTED_TAG):
                state.seen_ids.add(tr.tool_use_id)
                state.replacements[tr.tool_use_id] = tr.content
                decisions[tr.tool_use_id] = tr.content
                new_records.append(ContentReplacementRecord(
                    tool_use_id=tr.tool_use_id, replacement=tr.content,
                ))
            else:
                fresh.append(tr)

        # Pass 1：单条超限
        persisted_p1: set[str] = set()
        for tr in fresh:
            if len(tr.content) > SINGLE_RESULT_CHAR_LIMIT:
                fp = persist_tool_result(tr.tool_use_id, tr.content, session_dir)
                preview = make_persisted_preview(tr.content, fp)
                decisions[tr.tool_use_id] = preview
                state.replacements[tr.tool_use_id] = preview
                state.seen_ids.add(tr.tool_use_id)
                new_records.append(ContentReplacementRecord(
                    tool_use_id=tr.tool_use_id, replacement=preview,
                ))
                persisted_p1.add(tr.tool_use_id)

        # Pass 2：聚合超限
        remaining = [tr for tr in fresh if tr.tool_use_id not in persisted_p1]
        total = sum(len(c) for c in decisions.values()) + sum(
            len(tr.content) for tr in remaining
        )
        if total > AGGREGATE_CHAR_LIMIT:
            ranked = sorted(remaining, key=lambda tr: len(tr.content), reverse=True)
            for tr in ranked:
                if total <= AGGREGATE_CHAR_LIMIT:
                    break
                fp = persist_tool_result(tr.tool_use_id, tr.content, session_dir)
                preview = make_persisted_preview(tr.content, fp)
                old_len = len(tr.content)
                decisions[tr.tool_use_id] = preview
                state.replacements[tr.tool_use_id] = preview
                state.seen_ids.add(tr.tool_use_id)
                new_records.append(ContentReplacementRecord(
                    tool_use_id=tr.tool_use_id, replacement=preview,
                ))
                total -= old_len - len(preview)

        # 剩余未替换的 fresh 标记为"已见但未替换"
        for tr in fresh:
            if tr.tool_use_id not in state.replacements:
                state.seen_ids.add(tr.tool_use_id)
                decisions[tr.tool_use_id] = tr.content

        # 生成新的 tool_results，保持原始顺序
        new_tool_results = [
            ToolResultBlock(
                tool_use_id=tr.tool_use_id,
                content=decisions[tr.tool_use_id],
                is_error=tr.is_error,
            )
            for tr in msg.tool_results
        ]
        new_history.append(_copy_message_with_results(msg, new_tool_results))

    # Pass 3：在新 history 上执行工具感知的过期结果语义裁剪
    new_history = _snip_stale_messages(new_history, state.tool_names)

    new_conv = ConversationManager()
    new_conv.history = new_history
    new_conv.env_injected = conversation.env_injected
    new_conv.ltm_injected = conversation.ltm_injected
    new_conv.last_input_tokens = conversation.last_input_tokens
    new_conv.baseline_tokens = conversation.baseline_tokens
    new_conv.anchor_count = conversation.anchor_count

    return new_conv, new_records


# ---------------------------------------------------------------------------
# Layer 2：全对话摘要（Auto-Compact）
# ---------------------------------------------------------------------------

def compute_compact_threshold(context_window: int, manual: bool = False) -> int:
    effective = context_window - SUMMARY_OUTPUT_RESERVE
    margin = MANUAL_COMPACT_SAFETY_MARGIN if manual else AUTO_COMPACT_SAFETY_MARGIN
    return effective - margin


def should_auto_compact(last_input_tokens: int, context_window: int) -> bool:
    return last_input_tokens >= compute_compact_threshold(context_window)


SUMMARY_PROMPT = """\
你是一个对话摘要助手。你只能输出纯文本，不能调用任何工具。

请对下面的对话生成一份结构化摘要。

先在 <analysis> 标签中梳理对话中发生了什么（这部分会被丢弃），然后在 <summary> 标签中输出正式摘要。

<summary> 必须包含以下 9 个部分：

1. **主要请求和意图**：用户到底想做什么
2. **关键技术概念**：讨论过的重要技术点
3. **文件和代码段**：涉及哪些文件，关键代码片段要保留
4. **错误和修复**：遇到了什么错，怎么解决的
5. **问题解决过程**：解决问题的思路和方法
6. **所有用户消息**：用户说过的所有非工具结果的话（原文保留，不可改写！）
7. **待办任务**：还没完成的事
8. **当前工作**：最近在做什么（要最详细）
9. **可能的下一步**：接下来打算做什么

提醒：不要调用任何工具。工具调用会被拒绝，你会失败。只输出纯文本。"""


def extract_summary(llm_output: str) -> str:
    start = llm_output.find("<summary>")
    end = llm_output.find("</summary>")
    if start == -1 or end == -1:
        return llm_output
    return llm_output[start + len("<summary>"):end].strip()


def build_compact_messages(
    summary: str,
    attachment: str = "",
    has_keep_tail: bool = False,
    transcript_path: str = "",
) -> list[Message]:
    content = "本次会话延续自之前的对话，因上下文空间不足进行了压缩。以下是早期对话的摘要：\n\n" + summary
    if has_keep_tail:
        content += "\n\n近期消息已原样保留。"
    if transcript_path:
        content += f"\n\n如果你需要压缩前的具体细节（代码片段、报错信息等），请用 ReadFile 读取完整会话记录：{transcript_path}"
    if attachment:
        content += "\n\n---\n\n" + attachment
    return [
        Message(role="user", content=content),
    ]


# ---------------------------------------------------------------------------
# 压缩后恢复状态（支持 ReadFile 快照 + WriteFile/EditFile 写穿透更新）
# ---------------------------------------------------------------------------

RECOVERY_FILE_LIMIT = 5
RECOVERY_TOKENS_PER_FILE = 5_000
RECOVERY_SKILLS_BUDGET = 25_000
RECOVERY_TOKENS_PER_SKILL = 5_000
_RECOVERY_CHARS_PER_TOKEN = 3.5


@dataclass
class FileReadRecord:
    path: str
    content: str
    timestamp: float
    action: str = "read"  # "read" | "modified" | "created"


@dataclass
class SkillInvocationRecord:
    name: str
    body: str
    timestamp: float


class RecoveryState:
    """能在 Layer 2 压缩中存活下来的 per-agent 快照。

    支持写穿透（Write-Through）：不仅记录 ReadFile 返回的内容，当 WriteFile / EditFile
    修改文件时实时更新最新磁盘内容并记录变更状态，防止压缩后恢复旧代码产生幻觉。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._files: dict[str, FileReadRecord] = {}
        self._skills: dict[str, SkillInvocationRecord] = {}
        self._mutations: dict[str, str] = {}

    def record_file_read(self, path: str, content: str) -> None:
        if not path:
            return
        with self._lock:
            existing_action = self._mutations.get(path, "read")
            self._files[path] = FileReadRecord(
                path=path,
                content=content,
                timestamp=time.time(),
                action=existing_action,
            )

    def record_file_mutation(
        self, path: str, content: str, action: str = "modified"
    ) -> None:
        """记录 WriteFile / EditFile 产生的文件变更并同步刷新恢复快照。"""
        if not path:
            return
        with self._lock:
            self._mutations[path] = action
            self._files[path] = FileReadRecord(
                path=path,
                content=content,
                timestamp=time.time(),
                action=action,
            )

    def record_skill_invocation(self, name: str, body: str) -> None:
        if not name:
            return
        with self._lock:
            self._skills[name] = SkillInvocationRecord(
                name=name, body=body, timestamp=time.time()
            )

    def snapshot_files(self, limit: int) -> list[FileReadRecord]:
        with self._lock:
            records = list(self._files.values())
        records.sort(key=lambda r: r.timestamp, reverse=True)
        if limit > 0:
            records = records[:limit]
        return records

    def snapshot_mutations(self) -> dict[str, str]:
        with self._lock:
            return dict(self._mutations)

    def snapshot_skills(self) -> list[SkillInvocationRecord]:
        with self._lock:
            records = list(self._skills.values())
        records.sort(key=lambda r: r.timestamp, reverse=True)
        return records


def _approx_tokens(s: str) -> int:
    if not s:
        return 0
    return int(len(s) / _RECOVERY_CHARS_PER_TOKEN)


def _truncate_by_tokens(s: str, token_budget: int) -> str:
    if token_budget <= 0 or not s:
        return s
    if _approx_tokens(s) <= token_budget:
        return s
    max_chars = int(token_budget * _RECOVERY_CHARS_PER_TOKEN)
    if max_chars <= 0 or max_chars >= len(s):
        return s
    return s[:max_chars] + "\n… (内容已截断)"


def _first_line(s: str) -> str:
    for line in s.split("\n"):
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def build_recovery_attachment(
    state: RecoveryState | None,
    tool_schemas: list[Mapping[str, Any]] | None,
) -> str:
    """渲染压缩后恢复附件（最近读取/修改的文件、已修改文件清单、激活的技能、可用工具）。"""
    sections: list[str] = []

    if state is not None:
        mutations = state.snapshot_mutations()
        if mutations:
            mut_buf = ["## 本会话已修改的文件\n"]
            for m_path, m_action in mutations.items():
                mut_buf.append(f"- `{m_path}` ({m_action})\n")
            sections.append("".join(mut_buf))

        files = state.snapshot_files(RECOVERY_FILE_LIMIT)
        if files:
            buf = [
                "## 最近读过的文件\n",
                "以下快照是文件读取或写入工具最新记录的内容。如需当前字节请重新读取。\n",
            ]
            for rec in files:
                content = _truncate_by_tokens(rec.content, RECOVERY_TOKENS_PER_FILE)
                ts = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(rec.timestamp)
                )
                tag = f"{rec.action} {ts}" if rec.action != "read" else f"read {ts}"
                buf.append(f"### {rec.path}  ({tag})\n")
                buf.append("```\n")
                buf.append(content)
                if not content.endswith("\n"):
                    buf.append("\n")
                buf.append("```\n")
            sections.append("".join(buf))

        skills = state.snapshot_skills()
        if skills:
            buf = [
                "## 已激活的技能\n",
                "下列技能在本会话中被调用过，其触发条件仍然适用。\n",
            ]
            used = 0
            emitted = False
            for sk in skills:
                body = _truncate_by_tokens(sk.body, RECOVERY_TOKENS_PER_SKILL)
                tokens = _approx_tokens(body) + _approx_tokens(sk.name) + 8
                if used + tokens > RECOVERY_SKILLS_BUDGET:
                    break
                used += tokens
                buf.append(f"### {sk.name}\n\n{body}\n")
                emitted = True
            if emitted:
                sections.append("".join(buf))

    if tool_schemas:
        buf = [
            "## 可用工具\n",
            "你仍然可以调用以下工具，需要时直接发起调用即可：\n",
        ]
        for t in tool_schemas:
            name = t.get("name") if isinstance(t, Mapping) else None
            if not name:
                continue
            desc = t.get("description", "") if isinstance(t, Mapping) else ""
            desc = _first_line(desc or "")
            if desc:
                buf.append(f"- {name} — {desc}\n")
            else:
                buf.append(f"- {name}\n")
        sections.append("".join(buf))

    if not sections:
        return ""

    sections.append(
        "## 提示\n\n以上恢复的上下文是重建的。若需要原文代码、错误信息或用户原话，"
        "请用文件读取工具重新读取，不要根据摘要猜测细节。\n"
    )
    return "\n".join(sections)


def _group_messages_by_turn(messages: list[Message]) -> list[list[Message]]:
    groups: list[list[Message]] = []
    current: list[Message] = []
    for msg in messages:
        current.append(msg)
        if msg.role == "assistant" and not msg.tool_uses:
            groups.append(current)
            current = []
    if current:
        groups.append(current)
    return groups


def _message_tokens(msg: Message) -> int:
    return estimate_tokens([msg])


def _compute_keep_start_index(messages: list[Message]) -> int:
    """决定压缩时尾部要原样保留多少条消息，并自动对齐 Function Calling 配对约束。"""
    n = len(messages)
    if n == 0:
        return 0

    kept_tokens = 0
    kept_count = 0
    keep_start = n

    for i in range(n - 1, -1, -1):
        tok = _message_tokens(messages[i])

        if kept_count > 0 and kept_tokens + tok > KEEP_MAX_TOKENS:
            break

        kept_tokens += tok
        kept_count += 1
        keep_start = i

        if kept_tokens >= KEEP_RECENT_TOKENS or kept_count >= MIN_KEEP_MESSAGES:
            break

    return _align_keep_start_to_tool_pair(messages, keep_start)


def _align_keep_start_to_tool_pair(messages: list[Message], keep_start: int) -> int:
    """双向对齐 Function Calling 配对约束：
    1. 若 keep_start 落在携带 tool_results 的 user 消息上，向前回退到对应的 assistant(tool_use) 消息；
    2. 若 keep_start 落在末尾孤立的 assistant(tool_use) 消息上（无后续 tool_result），向后推进跳过该悬空调用。
    """
    while 0 < keep_start < len(messages):
        msg = messages[keep_start]
        if msg.role == "user" and msg.tool_results:
            prev = messages[keep_start - 1]
            if prev.role == "assistant" and prev.tool_uses:
                keep_start -= 1
                continue
        break

    # 若保留窗口起点是一条没有任何后续 tool_result 配对的悬空 assistant(tool_use)，向前跳过
    while keep_start < len(messages):
        msg = messages[keep_start]
        if msg.role == "assistant" and msg.tool_uses:
            has_matching_result = (
                keep_start + 1 < len(messages)
                and messages[keep_start + 1].role == "user"
                and bool(messages[keep_start + 1].tool_results)
            )
            if not has_matching_result:
                keep_start += 1
                continue
        break

    return keep_start


def _prefix_too_small_to_compact(prefix: list[Message]) -> bool:
    if not prefix:
        return True
    return estimate_tokens(prefix) < MIN_SUMMARIZE_PREFIX_TOKENS


# ---------------------------------------------------------------------------
# 熔断器
# ---------------------------------------------------------------------------


@dataclass
class CompactCircuitBreaker:
    max_failures: int = 3
    consecutive_failures: int = field(default=0, init=False)

    def record_failure(self) -> None:
        self.consecutive_failures += 1

    def record_success(self) -> None:
        self.consecutive_failures = 0

    def is_open(self) -> bool:
        return self.consecutive_failures >= self.max_failures


# ---------------------------------------------------------------------------
# Auto-compact 编排器
# ---------------------------------------------------------------------------

async def auto_compact(
    conversation: ConversationManager,
    client: Any,
    context_window: int,
    session_dir: Path,
    protocol: str = "anthropic",
    manual: bool = False,
    breaker: CompactCircuitBreaker | None = None,
    recovery: RecoveryState | None = None,
    tool_schemas: list[Mapping[str, Any]] | None = None,
    transcript_path: str = "",
) -> CompactEvent | str | None:
    threshold = compute_compact_threshold(context_window, manual=manual)
    current = conversation.current_tokens()

    if not manual and current < threshold:
        return None

    if not manual and breaker is not None and breaker.is_open():
        return "自动压缩已熔断（连续失败 3 次），请手动处理或使用 /compact"

    before_tokens = current

    keep_start = _compute_keep_start_index(conversation.history)
    to_summarize = conversation.history[:keep_start]
    keep_tail = conversation.history[keep_start:]

    if keep_start <= 0 or _prefix_too_small_to_compact(to_summarize):
        return None

    messages_for_summary = build_messages(list(to_summarize), protocol)

    summary_messages: list[dict[str, Any]] = [
        {"role": "user", "content": SUMMARY_PROMPT},
    ]
    summary_messages.extend(messages_for_summary)
    summary_messages.append(
        {"role": "user", "content": "请根据以上对话生成结构化摘要。记住：不要调用任何工具。"}
    )

    summary_conv = ConversationManager()
    summary_conv.history = [
        Message(role="user", content=SUMMARY_PROMPT),
    ]
    for msg in to_summarize:
        summary_conv.history.append(msg)
    summary_conv.history.append(
        Message(role="user", content="请根据以上对话生成结构化摘要。记住：不要调用任何工具。")
    )

    max_retries = 3
    llm_output: str | None = None

    for attempt in range(max_retries):
        try:
            from nexcode.tools.base import StreamEnd, StreamEvent, TextDelta

            collected_text = ""
            async for event in client.stream(summary_conv, system=SUMMARY_PROMPT):
                if isinstance(event, TextDelta):
                    collected_text += event.text
                elif isinstance(event, StreamEnd):
                    pass
            llm_output = collected_text
            break

        except Exception as e:
            err_msg = str(e).lower()
            if "prompt" in err_msg and "long" in err_msg or "too many" in err_msg:
                groups = _group_messages_by_turn(summary_conv.history[1:-1])
                drop_count = max(1, len(groups) // 5)
                remaining = groups[drop_count:]
                summary_conv.history = (
                    [summary_conv.history[0]]
                    + [m for g in remaining for m in g]
                    + [summary_conv.history[-1]]
                )
                continue
            if breaker is not None:
                breaker.record_failure()
            return f"摘要生成失败: {e}"

    if llm_output is None:
        if breaker is not None:
            breaker.record_failure()
        return "摘要生成失败：多次重试后仍超出上下文限制"

    summary = extract_summary(llm_output)
    attachment = build_recovery_attachment(recovery, tool_schemas)
    new_messages = build_compact_messages(
        summary,
        attachment=attachment,
        has_keep_tail=bool(keep_tail),
        transcript_path=transcript_path,
    )
    new_messages = new_messages + list(keep_tail)

    conversation.replace_history(new_messages)
    cleanup_tool_results(session_dir)

    if breaker is not None:
        breaker.record_success()

    return CompactEvent(
        before_tokens=before_tokens,
        boundary=CompactBoundary(summary=summary, keep=list(keep_tail)),
    )
