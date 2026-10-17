from __future__ import annotations

import re
import shlex

_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\s*$"), "递归强制删除根目录"),
    (re.compile(r"rm\s+-[a-z]*f[a-z]*r[a-z]*\s+/\s*$"), "递归强制删除根目录"),
    (re.compile(r"rm\s+.*--no-preserve-root"), "递归强制删除根目录"),
    (re.compile(r"mkfs\."), "格式化磁盘"),
    (re.compile(r"dd\s+if=.*of=/dev/"), "直接写磁盘设备"),
    (re.compile(r"chmod\s+-R\s+777\s+/"), "递归修改根目录权限"),
    (re.compile(r":\(\)\{\s*:\|:&\s*\};:"), "fork bomb"),
    (re.compile(r"curl\s+.*\|\s*(ba)?sh"), "管道执行远程脚本"),
    (re.compile(r"wget\s+.*\|\s*(ba)?sh"), "管道执行远程脚本"),
    (re.compile(r">\s*/dev/sd"), "覆盖磁盘设备"),
    (re.compile(r"\bfind\b.*\s-delete\b"), "find 批量删除文件 (-delete)"),
]


# 单词级只读安全命令（不含破坏性变体）
_SAFE_SINGLE_COMMANDS = frozenset({
    "ls", "dir", "pwd", "echo", "cat", "head", "tail", "wc",
    "find", "which", "whereis", "whoami", "hostname", "uname",
    "date", "cal", "uptime", "df", "du", "free", "env", "printenv",
    "file", "stat", "readlink", "realpath", "basename", "dirname",
    "sort", "uniq", "tr", "cut", "awk", "sed", "grep", "egrep", "fgrep",
    "diff", "comm", "true", "false", "test",
})

# 多词只读命令前缀
_SAFE_MULTI_WORD_PREFIXES: tuple[tuple[str, ...], ...] = (
    ("git", "status"),
    ("git", "log"),
    ("git", "diff"),
    ("git", "show"),
    ("git", "branch"),
    ("git", "tag"),
    ("git", "remote"),
    ("git", "rev-parse"),
    ("git", "ls-files"),
    ("git", "blame"),
    ("git", "stash", "list"),
    ("go", "version"),
    ("go", "env"),
    ("node", "-v"),
    ("npm", "-v"),
    ("python", "--version"),
    ("pip", "list"),
    ("cargo", "--version"),
    ("rustc", "--version"),
    ("java", "-version"),
    ("java", "--version"),
)

# 破坏只读属性的危险或写入参数黑名单（按命令名索引）
_UNSAFE_FLAGS_BY_CMD: dict[str, frozenset[str]] = {
    "find": frozenset({
        "-delete", "-exec", "-execdir", "-ok", "-okdir",
        "-fprint", "-fprint0", "-fprintf", "-fls",
    }),
    "sed": frozenset({"-i", "--in-place"}),
    "awk": frozenset({"-i", "inplace"}),
    "git_branch": frozenset({
        "-d", "-D", "--delete", "-m", "-M", "--move", "-c", "-C", "--copy",
        "--edit-description", "--set-upstream-to", "-u", "--unset-upstream",
    }),
    "git_tag": frozenset({"-d", "--delete", "-a", "-s", "-u", "-f", "--force"}),
    "git_remote": frozenset({
        "add", "remove", "rm", "rename", "set-url", "set-head", "set-branches", "prune",
    }),
}

_SHELL_CONTROL_CHARS = ("|", ";", "&&", "||", ">", "<", "$(", "`", "\n", "&")


def split_command_tokens(command: str) -> list[str] | None:
    """使用 shlex 安全分词；若引号不闭合或语法异常则返回 None。"""
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return None


def _has_unsafe_flags(cmd_key: str, args: list[str]) -> bool:
    unsafe = _UNSAFE_FLAGS_BY_CMD.get(cmd_key)
    if not unsafe:
        return False
    for arg in args:
        if arg in unsafe:
            return True
        # 处理 sed -i.bak 或短选项粘连（如 -iE）
        if cmd_key == "sed" and arg.startswith("-i"):
            return True
        if cmd_key == "git_branch" and arg.startswith(("-d", "-D", "-m", "-M")):
            return True
    return False


def is_safe_command(command: str) -> bool:
    """基于 shlex 词法分析判定命令是否为纯只读安全命令。"""
    trimmed = command.strip()
    if not trimmed:
        return False

    for ch in _SHELL_CONTROL_CHARS:
        if ch in trimmed:
            return False

    tokens = split_command_tokens(trimmed)
    if not tokens:
        return False

    head = tokens[0]
    rest = tokens[1:]

    # 检查多词安全前缀（如 git status, git branch 等）
    for prefix in _SAFE_MULTI_WORD_PREFIXES:
        plen = len(prefix)
        if len(tokens) >= plen and tuple(tokens[:plen]) == prefix:
            sub_args = tokens[plen:]
            cmd_key = "_".join(prefix)
            if _has_unsafe_flags(cmd_key, sub_args):
                return False
            return True

    # 检查单词安全命令（如 ls, find, sed, cat 等）
    if head in _SAFE_SINGLE_COMMANDS:
        if _has_unsafe_flags(head, rest):
            return False
        # awk 中若包含重定向或 system() 调用，拒绝视为只读命令
        if head == "awk" and any("system(" in a or ">" in a for a in rest):
            return False
        return True

    return False


class DangerousCommandDetector:
    """第一层：高危命令与破坏性词法特征检测器。"""

    def __init__(self, extra_patterns: list[tuple[str, str]] | None = None) -> None:
        self._patterns = list(_DANGEROUS_PATTERNS)
        if extra_patterns:
            for regex_str, reason in extra_patterns:
                self._patterns.append((re.compile(regex_str), reason))

    def detect(self, command: str) -> tuple[bool, str]:
        if not command:
            return False, ""

        for pattern, reason in self._patterns:
            if pattern.search(command):
                return True, reason

        # 词法级精细检测（支持分号、&&、||、管道连接的复合子命令）
        for sub_cmd in re.split(r"\s*(?:&&|\|\||;|\|)\s*", command):
            sub_cmd = sub_cmd.strip()
            if not sub_cmd:
                continue
            tokens = split_command_tokens(sub_cmd)
            if not tokens:
                continue
            cmd = tokens[0]
            args = tokens[1:]
            if cmd == "find" and "-delete" in args:
                return True, "find 批量删除文件 (-delete)"
            if cmd == "rm":
                has_rf = any(
                    a.startswith("-") and "r" in a.lower() and "f" in a.lower()
                    for a in args
                ) or (
                    any(a in ("-r", "-R", "--recursive") for a in args)
                    and any(a in ("-f", "--force") for a in args)
                )
                if has_rf and any(a in ("/", "/*", "~", "~/*") for a in args):
                    return True, "递归强制删除根目录或主目录"

        return False, ""
