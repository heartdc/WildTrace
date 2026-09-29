"""Joern CPG bridge for WildTrace — deep analysis backend.

Integrates Joern (Yamaguchi NDSS'14) as a code property graph analyzer
alongside the regex-based pattern scanners. Provides path-sensitive
analysis that regex cannot achieve.

Usage:
    from ohvul.joern_bridge import JoernAnalyzer
    analyzer = JoernAnalyzer(source_root)
    findings = analyzer.run_all_queries()

Robustness contract (audit 2026-09-29): when WSL/Joern is absent or slow,
every entry point degrades to False / [] instead of raising, and child
output is always decoded as UTF-8 with replacement so non-ASCII code
cannot crash the pipeline on cp936 hosts.
"""
from __future__ import annotations
import json, os, shlex, subprocess, tempfile, time
from dataclasses import dataclass, asdict, fields
from pathlib import Path

JOERN_HOME = os.environ.get("JOERN_HOME", "/opt/joern/joern-cli")
JOERN_PARSE = f"{JOERN_HOME}/joern-parse"
JOERN = f"{JOERN_HOME}/joern"
WSL_PREFIX = ["wsl", "-e"] if os.name == "nt" else []
_SUBPROCESS_TEXT = {"encoding": "utf-8", "errors": "replace"}


@dataclass
class JoernFinding:
    pattern: str; file: str; line: int; function: str
    detail: str; confidence: int


# Scala queries stored as separate script files (avoids escaping hell).
# Each query defines esc() so interpolated code/filenames cannot break
# the emitted JSON lines (quotes, backslashes, newlines are escaped).
_QUERY_J4 = r'''importCpg("__CPG__")
def esc(s: String): String = if (s == null) "" else s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "").replace("\t", " ")
cpg.call.name("memcpy|memmove|strcpy|strcat").foreach { c =>
  val args = c.argument.l
  if (args.size >= 3) {
    val src = args(1)
    val sizeArg = args(2)
    val isIdentifier = sizeArg.isInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Identifier]
    val enclosing = c.method
    val hasBound = enclosing.ast.isCall.name("strlen|sizeof|.*min.*|.*MAX.*").l.nonEmpty
    if (isIdentifier && !hasBound) {
      val j = s"""{"pattern":"J4","file":"${esc(enclosing.filename)}","line":${c.lineNumber.getOrElse(0)},"function":"${esc(enclosing.name)}","detail":"${esc(c.code)}","confidence":75}"""
      println(j)
    }
  }
}'''

_QUERY_J8 = r'''importCpg("__CPG__")
def esc(s: String): String = if (s == null) "" else s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "").replace("\t", " ")
cpg.call.name("free").foreach { fc =>
  val freedVar = fc.argument.l.headOption
  freedVar.foreach { v =>
    val varName = v match {
      case id: io.shiftleft.codepropertygraph.generated.nodes.Identifier => id.name
      case _ => ""
    }
    if (varName.nonEmpty) {
      val m = fc.method
      val uses = m.ast.isIdentifier.name(varName)
        .filter(_.lineNumber.getOrElse(0) > fc.lineNumber.getOrElse(0)).l
      val hasNullReset = m.ast.isCall
        .filter(_.code.contains(varName + " = ")).l.exists(_.code.contains("NULL"))
      if (uses.nonEmpty && !hasNullReset) {
        val j = s"""{"pattern":"J8","file":"${esc(m.filename)}","line":${fc.lineNumber.getOrElse(0)},"function":"${esc(m.name)}","detail":"${esc(varName + " freed then used " + uses.size + "x")}","confidence":80}"""
        println(j)
      }
    }
  }
}'''

_QUERY_J6 = r'''importCpg("__CPG__")
def esc(s: String): String = if (s == null) "" else s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "").replace("\t", " ")
cpg.method.filter(_.parameter.size > 0).foreach { m =>
  m.parameter.foreach { p =>
    val derefs = m.ast.isIdentifier.name(p.name).filter(_.inCall.nonEmpty).l.size
    val hasNullCheck = m.ast.isCall.filter(_.code.contains(p.name + " == ")).l.exists(_.code.contains("NULL"))
    if (derefs >= 3 && !hasNullCheck) {
      val j = s"""{"pattern":"J6","file":"${esc(m.filename)}","line":${m.lineNumber.getOrElse(0)},"function":"${esc(m.name)}","detail":"${esc(p.name + " " + derefs + " derefs no null check")}","confidence":${50 + derefs * 5}}"""
      println(j)
    }
  }
}'''

JOERN_QUERIES = {
    "J4_unbounded_copy": _QUERY_J4,
    "J6_null_deref": _QUERY_J6,
    "J8_use_after_free": _QUERY_J8,
}


def parse_finding_line(line: str):
    """Parse one stdout line into a JoernFinding; None if not parseable."""
    try:
        d = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(d, dict):
        return None
    known = {f.name for f in fields(JoernFinding)}
    kwargs = {k: v for k, v in d.items() if k in known}
    try:
        return JoernFinding(**kwargs)
    except TypeError:
        return None


class JoernAnalyzer:
    """Bridge to Joern CPG for deep vulnerability analysis."""

    def __init__(self, source_root, verbose=False):
        self.source_root = str(source_root)
        self.verbose = verbose
        self.cpg_path = None
        self._build_attempted = False

    def _to_wsl(self, path):
        s = str(path).replace('\\', '/')
        if len(s) > 1 and s[1] == ':':
            return f"/mnt/{s[0].lower()}{s[2:]}"
        return s

    def _bash(self, body: str) -> list:
        """Wrap a bash snippet with Joern env; paths quoted against spaces."""
        pre = (f"export PATH={shlex.quote(JOERN_HOME)}:$PATH; "
               f"export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64; ")
        return WSL_PREFIX + ["bash", "-c", pre + body]

    def _wsl_cmd(self, script_content):
        """Write script to temp file (LF endings) and build WSL command."""
        fd, script_path = tempfile.mkstemp(suffix='.sc')
        with os.fdopen(fd, 'wb') as f:
            f.write(script_content.encode('utf-8'))
        wsl_script = shlex.quote(self._to_wsl(script_path))
        cmd = self._bash(f"timeout 300 {shlex.quote(JOERN)} --script {wsl_script} 2>&1")
        return cmd, script_path

    def is_available(self):
        """True iff the Joern binaries are reachable; never raises."""
        try:
            cmd = self._bash(
                f"test -x {shlex.quote(JOERN_PARSE)} && test -x {shlex.quote(JOERN)} "
                f"&& echo OK || echo MISSING")
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=15, **_SUBPROCESS_TEXT)
            return "OK" in (r.stdout or "")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return False

    def build_cpg(self):
        """Build cpg.bin for the source root; False on any failure."""
        if self._build_attempted and not self.cpg_path:
            return False  # one attempt per analyzer, not one per query
        self._build_attempted = True
        wsl_src = shlex.quote(self._to_wsl(self.source_root))
        cpg_out = f"{self._to_wsl(self.source_root)}/cpg.bin"
        cmd = self._bash(
            f"timeout 600 {shlex.quote(JOERN_PARSE)} {wsl_src} "
            f"--output {shlex.quote(cpg_out)} 2>&1")
        if self.verbose:
            print(f"Building CPG for {wsl_src}...")
        t0 = time.time()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=660, **_SUBPROCESS_TEXT)
        except (OSError, subprocess.TimeoutExpired) as e:
            if self.verbose:
                print(f"  CPG build failed: {type(e).__name__}")
            return False
        elapsed = time.time() - t0
        out = (r.stdout or '') + (r.stderr or '')
        if "Successfully wrote" in out or (r.returncode == 0 and "Error" not in out[:200]):
            self.cpg_path = cpg_out
            if self.verbose:
                print(f"  CPG built in {elapsed:.1f}s")
            return True
        if self.verbose:
            print(f"  CPG build failed: {out[-200:]}")
        return False

    def run_query(self, query_name):
        if not self.cpg_path:
            if not self.build_cpg():
                return []
        template = JOERN_QUERIES.get(query_name)
        if not template:
            return []
        script = template.replace("__CPG__", self.cpg_path)
        cmd, script_path = self._wsl_cmd(script)
        t0 = time.time()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=330, **_SUBPROCESS_TEXT)
        except (OSError, subprocess.TimeoutExpired) as e:
            if self.verbose:
                print(f"  {query_name}: {type(e).__name__}")
            return []
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass
        elapsed = time.time() - t0

        findings = []
        for line in ((r.stdout or '') + (r.stderr or '')).splitlines():
            line = line.strip()
            if line.startswith('{"pattern"'):
                f = parse_finding_line(line)
                if f is not None:
                    findings.append(f)
        if self.verbose:
            print(f"  {query_name}: {len(findings)} findings in {elapsed:.1f}s")
        return findings

    def run_all_queries(self):
        if not self.cpg_path and not self.build_cpg():
            return []
        all_findings = []
        for qname in JOERN_QUERIES:
            all_findings.extend(self.run_query(qname))
        return all_findings
