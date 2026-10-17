from __future__ import annotations

import re
import shlex
import tempfile
from pathlib import Path

# 高敏文件与目录特征（保护密钥、凭证与环境机密不被自动篡改）
_SENSITIVE_FILENAMES = frozenset({
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "authorized_keys",
    "credentials",
})

_SENSITIVE_PATH_PARTS = frozenset({
    ".ssh",
    ".aws",
    ".gnupg",
})

# 文件读取/操作类命令，其参数中的路径需要纳入沙箱边界校验
_FILE_ACCESS_COMMANDS = frozenset({
    "cat", "head", "tail", "less", "more", "nl", "od", "xxd",
    "cp", "mv", "rm", "touch", "mkdir", "rmdir", "chmod", "chown",
    "sed", "awk", "grep", "egrep", "fgrep", "rg", "find",
    "file", "stat", "wc", "sort", "uniq", "diff", "comm",
})


class PathSandbox:
    """第二层：文件系统沙箱（目录边界校验 + 符号链接逃逸防御 + 高敏资产保护 + 命令内路径审计）。"""

    def __init__(
        self,
        project_root: str,
        extra_allowed: list[str] | None = None,
    ) -> None:
        root = Path(project_root).resolve()
        self._allowed_roots: list[Path] = [root, Path(tempfile.gettempdir()).resolve()]
        if extra_allowed:
            for p in extra_allowed:
                self._allowed_roots.append(Path(p).resolve())

    @property
    def project_root(self) -> Path:
        return self._allowed_roots[0]

    def check(self, path: str, is_write: bool = False) -> tuple[bool, str]:
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = self.project_root / p
        abs_path = p.absolute()

        try:
            real_path = abs_path.resolve(strict=True)
        except OSError:
            ancestor = abs_path
            while not ancestor.exists():
                parent = ancestor.parent
                if parent == ancestor:
                    return False, f"无法解析路径: {path}"
                ancestor = parent
            try:
                resolved_ancestor = ancestor.resolve(strict=True)
            except OSError:
                return False, f"无法解析路径: {path}"
            real_path = resolved_ancestor / abs_path.relative_to(ancestor)

        in_sandbox = False
        for root in self._allowed_roots:
            try:
                real_path.relative_to(root)
                in_sandbox = True
                break
            except ValueError:
                continue

        if not in_sandbox:
            return False, f"路径 {path} 超出沙箱范围"

        if is_write and self._is_sensitive_path(real_path):
            return False, f"路径 {path} 属于受保护的敏感文件，禁止直接写入"

        return True, ""

    @staticmethod
    def _is_sensitive_path(path: Path) -> bool:
        name = path.name.lower()
        if name in _SENSITIVE_FILENAMES or name.startswith(".env."):
            return True
        parts = {part.lower() for part in path.parts}
        if parts & _SENSITIVE_PATH_PARTS:
            return True
        return False

    def check_command_paths(self, command: str) -> tuple[bool, str]:
        """从 Shell 命令中提取显式文件路径参数并执行沙箱边界校验。"""
        if not command or not command.strip():
            return True, ""

        for sub_cmd in re.split(r"\s*(?:&&|\|\||;|\|)\s*", command):
            sub_cmd = sub_cmd.strip()
            if not sub_cmd:
                continue
            try:
                tokens = shlex.split(sub_cmd, posix=True)
            except ValueError:
                continue
            if not tokens:
                continue

            cmd = tokens[0]
            args = tokens[1:]

            for token in args:
                if token.startswith("-"):
                    continue
                # 识别显式跨目录或绝对路径：/etc/..., ~/..., ../...
                looks_like_explicit_path = (
                    token.startswith("/")
                    or token.startswith("~/")
                    or token == "~"
                    or token.startswith("../")
                    or "/../" in token
                )
                if not looks_like_explicit_path:
                    continue
                # 排除 URL 或常见非路径参数
                if "://" in token or token == "/dev/null":
                    continue
                if cmd in _FILE_ACCESS_COMMANDS or token.startswith(("/etc/", "/root/", "/var/", "/usr/", "~/.", "../")):
                    ok, reason = self.check(token, is_write=False)
                    if not ok:
                        return False, reason

        return True, ""
