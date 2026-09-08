
# core/ado_git.py
#
# Vendored from yapl-upgrader's core/ado_git.py (verbatim). Kept as a direct copy
# so daily-dashboard has no cross-repo dependency on yapl-upgrader; re-sync by hand
# if the source project fixes a bug here.
import base64
import os
import re
import html
import shlex
import subprocess
from pathlib import Path
from typing import Optional
import requests
from urllib.parse import urlparse, urlunparse, quote, unquote


class GitCommandError(subprocess.CalledProcessError):
    def __init__(
        self,
        returncode: int,
        cmd,
        *,
        stdout: str = "",
        stderr: str = "",
        cwd: Optional[Path] = None,
        hint: Optional[str] = None,
    ):
        super().__init__(returncode, cmd, output=stdout, stderr=stderr)
        self.cwd = str(cwd) if cwd is not None else None
        self.hint = hint

    @staticmethod
    def _redact(text: str) -> str:
        value = text or ""
        value = re.sub(r"(AUTHORIZATION:\s*Basic\s+)[^\s'\"]+", r"\1<redacted>", value, flags=re.IGNORECASE)
        value = re.sub(r"(https?://)([^/@\s]+)@", r"\1<redacted>@", value, flags=re.IGNORECASE)
        return value

    @classmethod
    def _format_cmd(cls, cmd) -> str:
        if isinstance(cmd, (list, tuple)):
            return " ".join(shlex.quote(cls._redact(str(part))) for part in cmd)
        return cls._redact(str(cmd))

    def __str__(self) -> str:
        parts = [f"git command failed with exit code {self.returncode}"]
        if self.cwd:
            parts.append(f"cwd: {self.cwd}")
        if self.cmd:
            parts.append(f"command: {self._format_cmd(self.cmd)}")

        stderr = (self.stderr or "").strip()
        stdout = (self.stdout or "").strip()
        if stderr:
            parts.append(f"stderr:\n{self._redact(stderr)}")
        elif stdout:
            parts.append(f"stdout:\n{self._redact(stdout)}")

        if self.hint:
            parts.append(f"hint: {self.hint}")
        return "\n".join(parts)

class AdoGit:
    """
    Azure DevOps Git helper with non-interactive HTTPS authentication.
    """

    def __init__(self, org_url: str, project: str, repo: str, pat: str,
                 use_url_embedded_pat: bool = False):
        # Sanitize & normalize inputs (strip HTML, unescape, trim)
        def _sanitize(s: str) -> str:
            s = html.unescape(s or "")
            s = re.sub(r"<[^>]+>", "", s)  # remove any pasted <a>...</a> etc.
            return s.strip()

        self.org_url = _sanitize(org_url).rstrip("/")            # e.g. https://dev.azure.com/<org>
        self.project = _sanitize(project)                        # raw project name (may contain spaces)
        self.repo = _sanitize(repo)                              # repo name or GUID
        self.pat = pat
        self.use_url_embedded_pat = use_url_embedded_pat
        self.repo_url = None

        # REST headers
        self._rest_headers = {
            "Authorization": self._basic_header(pat),
            "Content-Type": "application/json",
        }

        # Disable interactive prompts for git
        os.environ.setdefault("GIT_TERMINAL_PROMPT", "0")
        os.environ.setdefault("GIT_ASKPASS", "echo")

    def _infer_from_ado_url(self, url: str) -> tuple[str, str, str]:
        """Best-effort parse of common Azure DevOps repo URL formats.

        Returns (org_url, project, repo) where org_url is like:
          - https://dev.azure.com/<org>
        """
        url = (url or "").strip()
        if not url:
            return "", "", ""

        # SSH form: git@ssh.dev.azure.com:v3/<org>/<project>/<repo>
        m = re.match(r"^git@ssh\.dev\.azure\.com:v3/([^/]+)/([^/]+)/([^/]+)$", url)
        if m:
            org, project, repo = m.group(1), unquote(m.group(2)), unquote(m.group(3))
            repo = repo[:-4] if repo.lower().endswith(".git") else repo
            return f"https://dev.azure.com/{org}", project, repo

        try:
            parsed = urlparse(url)
        except Exception:
            return "", "", ""

        host = (parsed.hostname or "").lower()
        parts = [p for p in (parsed.path or "").split("/") if p]

        # https://dev.azure.com/<org>/<project>/_git/<repo>
        if host == "dev.azure.com" and len(parts) >= 4 and parts[2].lower() == "_git":
            org = parts[0]
            project = unquote(parts[1])
            repo = unquote(parts[3])
            repo = repo[:-4] if repo.lower().endswith(".git") else repo
            return f"{parsed.scheme}://{parsed.hostname}/{org}", project, repo

        # https://<org>.visualstudio.com/<project>/_git/<repo>
        if host.endswith(".visualstudio.com") and len(parts) >= 3 and parts[1].lower() == "_git":
            org = host.split(".")[0]
            project = unquote(parts[0])
            repo = unquote(parts[2])
            repo = repo[:-4] if repo.lower().endswith(".git") else repo
            return f"{parsed.scheme}://dev.azure.com/{org}", project, repo

        return "", "", ""

    def _try_infer_repo_context(self, *, repo_dir: Optional[Path] = None) -> None:
        """Populate missing org/project/repo using known URLs or the local git remote."""
        candidates: list[str] = []
        if isinstance(self.repo_url, str) and self.repo_url.strip():
            candidates.append(self.repo_url.strip())

        if repo_dir is not None:
            try:
                self._ensure_safe_directory(repo_dir)
                r = subprocess.run(
                    ["git", "config", "--get", "remote.origin.url"],
                    cwd=repo_dir,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                if r.returncode == 0 and (r.stdout or "").strip():
                    candidates.append((r.stdout or "").strip())
            except Exception:
                pass

        for u in candidates:
            org_url, project, repo = self._infer_from_ado_url(u)
            if (not self.org_url) and org_url:
                self.org_url = org_url.rstrip("/")
            if (not self.project) and project:
                self.project = project
            if (not self.repo) and repo:
                self.repo = repo

        # If we still don't have repo/project, don't silently create bad API URLs.
        if not self.org_url or not self.project or not self.repo:
            # Leave as-is; caller decides whether to error.
            return

    def _ensure_repo_context(self, *, repo_dir: Optional[Path] = None) -> None:
        self._try_infer_repo_context(repo_dir=repo_dir)
        missing = [k for k, v in (("org_url", self.org_url), ("project", self.project), ("repo", self.repo)) if not v]
        if missing:
            hint = (
                "Missing Azure DevOps context: "
                + ", ".join(missing)
                + ". Provide org_url/project/repo when constructing AdoGit, "
                "or ensure the checked-out repo has an Azure DevOps 'origin' remote."
            )
            raise ValueError(hint)

    def _basic_header(self, token: str) -> str:
        # Authorization: Basic base64(":PAT")
        raw = f":{token}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("utf-8")

    def _ensure_safe_directory(self, repo_dir: Optional[Path]) -> None:
        if repo_dir is None:
            return
        try:
            resolved = Path(repo_dir).resolve()
        except Exception:
            resolved = Path(repo_dir)
        subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", str(resolved)],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    def _run(self, args, cwd: Optional[Path] = None, check: bool = True):
        self._ensure_safe_directory(cwd)
        header_key = "http.https://dev.azure.com/.extraheader"
        header_val = f"AUTHORIZATION: {self._basic_header(self.pat)}"
        cmd = ["git", "-c", f"{header_key}={header_val}"] + args
        result = subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and result.returncode != 0:
            raise GitCommandError(
                result.returncode,
                cmd,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                cwd=cwd,
            )
        return result

    def _embed_pat_in_url(self, url: str) -> str:
        parsed = urlparse(url)
        netloc = f"anything:{self.pat}@{parsed.netloc}"
        return urlunparse(parsed._replace(netloc=netloc))

    def _has_staged_changes(self, repo_dir):
        self._ensure_safe_directory(repo_dir)
        result = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=repo_dir)
        return result.returncode != 0  # True if there are staged changes

    # ---------- Public methods ----------
    def clone_or_pull(self, repo_url: str, workdir: Path) -> Path:
        repo_dir = workdir
        repo_dir.parent.mkdir(parents=True, exist_ok=True)

        # sanitize repo_url in case it contains pasted HTML
        repo_url = html.unescape(re.sub(r"<[^>]+>", "", repo_url)).strip()

        # Record URL and infer missing repo/project/org as early as possible.
        self.repo_url = repo_url
        try:
            self._try_infer_repo_context(repo_dir=repo_dir if (repo_dir / ".git").exists() else None)
        except Exception:
            pass

        if repo_dir.exists() and (repo_dir / ".git").exists():
            self._run(["fetch", "--all"], cwd=repo_dir, check=False)
            return repo_dir

        url = repo_url
        if self.use_url_embedded_pat:
            url = self._embed_pat_in_url(repo_url)

        try:
            self._run(["clone", url, str(repo_dir)], check=True)
            return repo_dir
        except subprocess.CalledProcessError as e:
            hint = (
                "Git clone failed. Ensure a PAT with 'Code (Read & write)' scope is valid. "
                "We inject Authorization via `git -c http.extraheader`. If your environment "
                "strips extra headers, set use_url_embedded_pat=True (less secure) or use SSH."
            )
            if isinstance(e, GitCommandError):
                raise GitCommandError(
                    e.returncode,
                    e.cmd,
                    stdout=e.stdout or "",
                    stderr=e.stderr or "",
                    cwd=repo_dir.parent,
                    hint=hint,
                ) from e
            raise GitCommandError(
                e.returncode,
                e.cmd,
                stdout=getattr(e, "stdout", "") or getattr(e, "output", "") or "",
                stderr=getattr(e, "stderr", "") or "",
                cwd=repo_dir.parent,
                hint=hint,
            ) from e

    def checkout_branch(self, repo_dir: Path, branch: str):
        self._run(["fetch", "origin", "--prune"], cwd=repo_dir, check=False)
        r = self._run(["rev-parse", "--verify", branch], cwd=repo_dir, check=False)
        if r.returncode != 0:
            self._run(["checkout", "-B", branch, f"origin/{branch}"], cwd=repo_dir, check=True)
        else:
            self._run(["checkout", branch], cwd=repo_dir, check=True)
        self._run(["pull", "--ff-only"], cwd=repo_dir, check=False)

    def create_branch(self, repo_dir: Path, feature_branch: str):
        # Create the branch if it doesn't exist; if it exists on origin, base it on origin/<branch>.
        self._run(["fetch", "origin", "--prune"], cwd=repo_dir, check=False)
        remote_ref = f"refs/remotes/origin/{feature_branch}"
        r = self._run(["show-ref", "--verify", "--quiet", remote_ref], cwd=repo_dir, check=False)
        if r.returncode == 0:
            self._run(["checkout", "-B", feature_branch, f"origin/{feature_branch}"], cwd=repo_dir, check=True)
        else:
            self._run(["checkout", "-B", feature_branch], cwd=repo_dir, check=True)

    def checkout_local_branch(self, repo_dir: Path, branch: str):
        """Checkout a local branch, creating/resetting it if needed.

        Unlike `checkout_branch`, this does not require the branch to exist on origin.
        """
        if not branch or branch.lower() == "none":
            raise ValueError("branch must be a valid branch name")

        r = self._run(["rev-parse", "--verify", branch], cwd=repo_dir, check=False)
        if r.returncode == 0:
            self._run(["checkout", branch], cwd=repo_dir, check=True)
            return

        # Create/reset from current HEAD
        self._run(["checkout", "-B", branch], cwd=repo_dir, check=True)

    def commit_all(self, repo_dir: Path, msg: str):
        self._run(["add", "-A"], cwd=repo_dir, check=True)
        if self._has_staged_changes(repo_dir):
            # sanitize message (convert HTML entities like &amp; to &)
            safe_msg = html.unescape(msg or "")
            self._run(["commit", "-m", safe_msg], cwd=repo_dir, check=True)
            self._run(["push", "-u", "origin", "HEAD"], cwd=repo_dir, check=True)
        else:
            print("✅ No changes to commit. Skipping git commit.")

    def commit_paths(self, repo_dir: Path, paths: list[Path], msg: str):
        """Stage and commit only the specified paths.

        This is useful when the workspace contains generated artifacts that must not be committed.
        """
        repo_dir = Path(repo_dir)
        unique: list[str] = []
        seen: set[str] = set()
        for p in paths or []:
            if not p:
                continue
            pp = Path(p)
            if not pp.exists():
                continue
            try:
                rel = pp.relative_to(repo_dir)
                s = rel.as_posix()
            except Exception:
                s = str(pp)
            if s and s not in seen:
                seen.add(s)
                unique.append(s)

        if not unique:
            print("✅ No paths to commit. Skipping git commit.")
            return False

        # Stage only requested files.
        self._run(["add", "--"] + unique, cwd=repo_dir, check=True)
        if self._has_staged_changes(repo_dir):
            safe_msg = html.unescape(msg or "")
            self._run(["commit", "-m", safe_msg], cwd=repo_dir, check=True)
            self._run(["push", "-u", "origin", "HEAD"], cwd=repo_dir, check=True)
            return True
        else:
            print("✅ No changes to commit. Skipping git commit.")
            return False

    def _normalize_ref(self, branch_or_ref: str, *, kind: str = "heads") -> str:
        v = (branch_or_ref or "").strip()
        if not v:
            raise ValueError("branch name must be non-empty")
        if v.startswith("refs/"):
            return v
        if kind == "heads":
            return f"refs/heads/{v}"
        return f"refs/{kind}/{v}"

    def _repo_api_base(self) -> str:
        # Ensure we never produce .../repositories//... URLs.
        self._ensure_repo_context()
        # Avoid double-encoding: decode once, then encode exactly once
        proj = quote(unquote(self.project), safe="")
        repo = quote(unquote(self.repo), safe="")
        return f"{self.org_url}/{proj}/_apis/git/repositories/{repo}"

    def _find_active_pr(self, *, source_ref: str, target_ref: str) -> Optional[str]:
        """Return an existing active PR web URL for source/target, if present."""
        url = f"{self._repo_api_base()}/pullrequests"
        params = {
            "api-version": "7.1",
            "searchCriteria.status": "active",
            "searchCriteria.sourceRefName": source_ref,
            "searchCriteria.targetRefName": target_ref,
        }
        r = requests.get(url, headers=self._rest_headers, params=params, timeout=30)
        if r.status_code >= 400:
            return None
        data = r.json() or {}
        values = data.get("value") or []
        if not values:
            return None

        pr = values[0] or {}
        web = ((pr.get("_links") or {}).get("web") or {}).get("href")
        if isinstance(web, str) and web.strip():
            return web
        repo_web = ((pr.get("repository") or {}).get("webUrl") or "").strip()
        pr_id = pr.get("pullRequestId")
        if repo_web and pr_id is not None:
            return f"{repo_web}/pullrequest/{pr_id}"
        return None

    def create_pr(
        self,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str,
        *,
        repo_url: Optional[str] = None,
        repo_dir: Optional[Path] = None,
    ) -> str:
        """
        Create an ADO Pull Request. Requires that the source branch already exists on origin.
        """
        if not source_branch or source_branch.lower() == "none":
            raise ValueError("source_branch must be a valid branch name (got None).")
        if source_branch.strip() == target_branch.strip():
            raise ValueError("source_branch and target_branch must be different.")

        source_ref = self._normalize_ref(source_branch, kind="heads")
        target_ref = self._normalize_ref(target_branch, kind="heads")

        if repo_url:
            self.repo_url = html.unescape(re.sub(r"<[^>]+>", "", repo_url)).strip()

        # In case the instance was created without repo info, try to infer from local checkout.
        self._try_infer_repo_context(repo_dir=None)
        if repo_dir is not None:
            self._try_infer_repo_context(repo_dir=repo_dir)

        existing = self._find_active_pr(source_ref=source_ref, target_ref=target_ref)
        if existing:
            return existing

        url = f"{self._repo_api_base()}/pullrequests"
        payload = {
            "sourceRefName": source_ref,
            "targetRefName": target_ref,
            "title": html.unescape(title or ""),
            "description": html.unescape(description or ""),
        }

        r = requests.post(url, headers=self._rest_headers, json=payload, params={"api-version": "7.1"}, timeout=30)
        if r.status_code >= 400:
            body = r.text
            # Add diagnostics to make troubleshooting straightforward
            msg = (
                f"{r.status_code} Error creating PR at {url}\n"
                f"Payload={payload}\n"
                f"Response={body}\n"
                f"Hints: Check project/repo spelling, ensure branches exist on remote, "
                f"and confirm PAT has Code (Read & write) & PR permissions."
            )
            raise requests.HTTPError(msg, response=r)

        pr = r.json() or {}
        web = ((pr.get("_links") or {}).get("web") or {}).get("href")
        if isinstance(web, str) and web.strip():
            return web

        repo_web = ((pr.get("repository") or {}).get("webUrl") or "").strip()
        pr_id = pr.get("pullRequestId")
        if repo_web and pr_id is not None:
            return f"{repo_web}/pullrequest/{pr_id}"
        return pr.get("url", "") or ""
