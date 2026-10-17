#!/usr/bin/env python3
"""LLM PoC compile-execute feedback loop (steps ① and ②).

Step ①: generate → compile in WSL → on error, feed stderr back to LLM
Step ②: on compile success → execute → check SIGSEGV/ASan

The PoC compiles standalone with host gcc + ASan (stub types, no OHOS
sysroot needed). A SIGSEGV (exit 139) or ASan report from the PoC
proves the trigger logic is correct — the real-library confirmation
(step ④) then uses the same trigger against the actual .so.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .llm_adapter import chat_completion, LlmTransportError
from .llm_poc import (
    _build_prompt,
    _extract_code_block,
    _extract_context,
    _extract_includes,
    _extract_semantic_context,
    _validate_poc,
    runtime_key,
)


def _wsl_exec(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Execute a command in WSL Ubuntu, return (exit_code, stdout, stderr)."""
    full = ["wsl", "-d", "Ubuntu", "--"] + cmd
    proc = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def compile_poc(code: str, work_dir: str) -> dict:
    """Compile PoC with gcc -fsanitize=address in WSL.

    Returns {ok, binary_path, stderr} — binary_path is a WSL path.
    """
    src = Path(work_dir) / "poc.c"
    bin_path = Path(work_dir) / "poc"
    src.write_text(code, encoding="utf-8")

    wsl_src = _to_wsl_path(src)
    wsl_bin = _to_wsl_path(bin_path)
    rc, stdout, stderr = _wsl_exec([
        "gcc", "-fsanitize=address", "-g", "-O0",
        "-o", wsl_bin, wsl_src, "-ldl",
    ], timeout=30)

    return {
        "ok": rc == 0,
        "binary_path": str(bin_path) if rc == 0 else None,
        "wsl_binary": wsl_bin if rc == 0 else None,
        "stderr": stderr[:2000] if stderr else "",
        "stdout": stdout[:500] if stdout else "",
    }


def execute_poc(wsl_binary: str, timeout: int = 10) -> dict:
    """Execute compiled PoC in WSL, capture exit code and output.

    Returns {exit_code, stdout, stderr, crashed, asan_report}.
    """
    try:
        rc, stdout, stderr = _wsl_exec(
            ["bash", "-c", f"timeout {timeout} {wsl_binary} 2>&1; echo EXIT:$?"],
            timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": "timeout",
                "crashed": False, "asan_report": ""}

    # parse exit code from the last line
    lines = stdout.strip().splitlines()
    exit_code = -1
    for line in reversed(lines):
        m = re.match(r"EXIT:(\d+)", line)
        if m:
            exit_code = int(m.group(1))
            lines = lines[:-1]  # remove the EXIT line
            break

    output = "\n".join(lines)
    crashed = exit_code in (139, 134, 134 + 64) or "AddressSanitizer" in output
    asan_report = ""
    if "AddressSanitizer" in output:
        # extract the ASan summary
        for line in output.splitlines():
            if "ERROR: AddressSanitizer" in line:
                asan_report = line.strip()
                break

    return {
        "exit_code": exit_code,
        "stdout": output[:2000],
        "stderr": stderr[:500],
        "crashed": crashed,
        "asan_report": asan_report,
    }


def _to_wsl_path(win_path) -> str:
    """Convert Windows path to WSL path (C:\\foo → /mnt/c/foo)."""
    p = str(win_path).replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def _build_retry_prompt(finding_dict: dict, original_code: str,
                        compile_error: str,
                        semantic_context: str = "") -> list[dict]:
    """Build a retry prompt with the compilation error for the LLM to fix."""
    system = (
        "You are fixing a C PoC that failed to compile. The original code "
        "and the compiler error are below. Fix the compilation errors and "
        "return the corrected complete program. Keep the same trigger logic."
    )
    user = (
        f"## Original PoC (failed to compile)\n"
        f"```c\n{original_code[:3000]}\n```\n"
        f"\n## Compiler Error\n"
        f"```\n{compile_error[:1500]}\n```\n"
        f"\nFix all compilation errors and return the complete corrected "
        f"C program in a single code block."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _build_real_library_prompt(finding_dict: dict, library_symbols: str,
                               library_path: str) -> list[dict]:
    """Build a prompt for generating a dlopen-based FFI client PoC that
    calls the real library's exported symbols (step ④)."""
    system = (
        "You are writing a minimal FFI validation client for an OpenHarmony "
        "shared library vulnerability. The client uses dlopen/dlsym to call "
        "the real library and triggers the null-pointer dereference. Rules:\n"
        "1. Write ONLY C code in a single code block.\n"
        "2. Use #include <dlfcn.h> and #include <stdio.h>.\n"
        "3. Define minimal struct stubs matching the library's ABI.\n"
        "4. dlopen the library from argv[1], dlsym the target function.\n"
        "5. Call it with the malformed input described in the finding.\n"
        "6. A crash (SIGSEGV) is EXPECTED — it proves the vulnerability.\n"
        "7. Print a marker line before calling so the runner can identify "
        "the test case.\n"
        "8. Do NOT spawn processes, open network connections, or delete files.\n"
    )
    user = (
        f"## Target Library\n"
        f"Path: {library_path}\n"
        f"Exported symbols:\n{library_symbols[:2000]}\n"
        f"\n## Finding\n"
        f"Function: {finding_dict.get('function', '?')}\n"
        f"Struct/Type: {finding_dict.get('struct_type', '?')}\n"
        f"Description: {finding_dict.get('description', '')[:300]}\n"
        f"Trigger: {finding_dict.get('trigger_hint', '')}\n"
        f"CWE: {finding_dict.get('cwe', '?')}\n"
        f"\nWrite a C FFI client that dlopens the library and calls the "
        f"target function with the malformed input that triggers the bug."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def generate_real_library_poc(finding_dict: dict, library_path: str,
                              library_symbols: str, *,
                              api_key: str | None = None,
                              model: str = 'glm-5.3',
                              base_url: str = 'https://api.z.ai/api/anthropic',
                              timeout: int = 120,
                              max_tokens: int = 2048) -> dict:
    """Step ④: generate a dlopen-based PoC against the real library,
    compile it with the OHOS clang, and execute it via the musl loader.

    Returns the standard result dict plus real_library_verified.
    """
    messages = _build_real_library_prompt(
        finding_dict, library_symbols, library_path)

    try:
        key = runtime_key(api_key)
        result = chat_completion(
            messages, base_url=base_url, model=model,
            timeout=timeout, max_tokens=max_tokens,
            api_key=key, json_mode=False)
    except (LlmTransportError, ValueError) as exc:
        return {'code': None, 'error': str(exc), 'model': model}

    code = _extract_code_block(result.get('content', ''))
    if not code:
        return {'code': None, 'error': 'no_code_block_in_response',
                'model': model}

    return {
        'code': code,
        'model': result.get('reported_model', model),
        'sha256': hashlib.sha256(code.encode('utf-8')).hexdigest(),
        'real_library_target': library_path,
    }


def verify_against_real_library(poc_code: str, oh_root: str,
                                build_output: str, library_rel: str,
                                evidence_dir: str) -> dict:
    """Compile the LLM-generated PoC and execute it against the real
    library using the existing run_malformed.sh infrastructure."""
    evidence = Path(evidence_dir)
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "llm_client.c").write_text(poc_code, encoding="utf-8")

    # use the validation harness's compile-execute pattern
    llvm = f"{oh_root}/prebuilts/clang/ohos/linux-x86_64/llvm"
    sysroot = f"{build_output}/obj/third_party/musl"
    runtime = f"{sysroot}/usr/lib/x86_64-linux-ohos/libc.so"
    library = f"{build_output}/{library_rel}"

    # compile
    rc, stdout, stderr = _wsl_exec([
        f"{llvm}/bin/clang", "--target=x86_64-linux-ohos",
        f"--sysroot={sysroot}",
        f"-I{sysroot}/usr/include/x86_64-linux-ohos",
        str(evidence / "llm_client.c"),
        f"-L{sysroot}/usr/lib/x86_64-linux-ohos",
        "-o", str(evidence / "llm_client"),
    ], timeout=30)
    if rc != 0:
        return {'real_library_verified': False,
                'compile_error': stderr[:1000]}

    # collect library dirs for the loader
    all_dirs = _wsl_exec([
        "bash", "-c",
        f"find {build_output} -name '*.z.so' -not -path '*/obj/*' "
        f"-exec dirname {{}} \\; | sort -u | tr '\\n' ':'"
    ], timeout=30)[1].strip()
    libdirs = f"{sysroot}/usr/lib/x86_64-linux-ohos:{all_dirs}"

    # execute
    rc, stdout, stderr = _wsl_exec([
        "bash", "-c",
        f"timeout 10 {runtime} --library-path {libdirs} "
        f"{evidence}/llm_client {library} 2>&1; echo EXIT:$?"
    ], timeout=20)

    exit_code = -1
    for line in reversed(stdout.strip().splitlines()):
        m = re.match(r"EXIT:(\d+)", line)
        if m:
            exit_code = int(m.group(1))
            break

    crashed = exit_code in (139, 134) or "AddressSanitizer" in stdout

    return {
        'real_library_verified': True,
        'crashed': crashed,
        'exit_code': exit_code,
        'output': stdout[:2000],
        'evidence_dir': str(evidence),
    }


def generate_poc_with_verification(finding_dict: dict, source_root: Path, *,
                                   api_key: str | None = None,
                                   model: str = 'glm-5.3',
                                   base_url: str = 'https://api.z.ai/api/anthropic',
                                   timeout: int = 60,
                                   max_tokens: int = 2048,
                                   max_compile_retries: int = 2,
                                   execute_timeout: int = 10) -> dict:
    """Full loop: generate → compile → retry on error → execute → verify.

    Returns the generate_poc_llm result dict augmented with:
      compiled: bool
      compile_stderr: str (if failed)
      binary_path: str (if compiled)
      executed: bool
      exit_code: int
      crashed: bool
      asan_report: str
    """
    # Step 1: initial generation (same as generate_poc_llm)
    from .llm_poc import generate_poc_llm
    result = generate_poc_llm(
        finding_dict, source_root,
        api_key=api_key, model=model, base_url=base_url,
        timeout=timeout, max_tokens=max_tokens)

    result.setdefault('compiled', False)
    result.setdefault('executed', False)
    result.setdefault('crashed', False)

    if result.get('code') is None:
        return result  # generation failed

    # Step 2: compile-execute loop
    with tempfile.TemporaryDirectory(prefix="wt_poc_") as work_dir:
        code = result['code']
        compile_result = compile_poc(code, work_dir)

        # Step ①: retry loop on compile failure
        retry_count = 0
        while not compile_result["ok"] and retry_count < max_compile_retries:
            retry_count += 1
            try:
                key = runtime_key(api_key)
                retry_messages = _build_retry_prompt(
                    finding_dict, code, compile_result["stderr"])
                retry_result = chat_completion(
                    retry_messages,
                    base_url=base_url, model=model,
                    timeout=timeout, max_tokens=max_tokens,
                    api_key=key, json_mode=False)
                fixed_code = _extract_code_block(
                    retry_result.get('content', ''))
                if fixed_code and len(fixed_code) > 25:
                    code = fixed_code
                    compile_result = compile_poc(code, work_dir)
                else:
                    break
            except (LlmTransportError, ValueError):
                break

        result['code'] = code  # may have been fixed in retries
        result['compile_retries'] = retry_count

        if not compile_result["ok"]:
            result['compiled'] = False
            result['compile_stderr'] = compile_result["stderr"]
            return result

        result['compiled'] = True
        result.pop('compile_stderr', None)

        # Step ②: execute and check for crash
        exec_result = execute_poc(
            compile_result["wsl_binary"], timeout=execute_timeout)
        result['executed'] = True
        result['exit_code'] = exec_result['exit_code']
        result['crashed'] = exec_result['crashed']
        result['asan_report'] = exec_result['asan_report']
        result['execution_output'] = exec_result['stdout'][:1000]

    return result
