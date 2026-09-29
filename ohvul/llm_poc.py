"""LLM-powered PoC generation from autopilot findings.

Takes a Finding (from ohvul.autopilot) + surrounding source code context,
sends them to an LLM, and receives a compilable C PoC that exercises
the vulnerable code path with correct types and function signatures.

This upgrades PoC from "template with TODO comments" to "actual code
that compiles and triggers the vulnerability".

Usage:
    from ohvul.llm_poc import generate_poc_llm
    poc_code = generate_poc_llm(finding, source_root, api_key=os.environ['KEY'])

    # Or batch:
    from ohvul.llm_poc import batch_generate
    results = batch_generate(findings, source_root, output_dir, api_key)
"""
from __future__ import annotations
import json, os, re, hashlib
from pathlib import Path

from .llm_adapter import chat_completion, LlmTransportError, runtime_key

MAX_SOURCE_CONTEXT = 3000   # characters of source code to include
MAX_FINDINGS_PER_BATCH = 10


def _extract_context(source_root: Path, file: str, line: int,
                     context_lines: int = 15) -> str:
    """Read source file around the finding, return trimmed context."""
    src = source_root / file
    if not src.exists():
        return f"(source file {file} not found)"
    try:
        text = src.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return f"(cannot read {file})"
    lines = text.splitlines()
    start = max(0, line - context_lines - 1)
    end = min(len(lines), line + context_lines)
    snippet = '\n'.join(f"{i+1:4d}| {lines[i]}" for i in range(start, end))
    return snippet[:MAX_SOURCE_CONTEXT]


def _extract_includes(source_root: Path, file: str) -> str:
    """Extract #include lines from the source file."""
    src = source_root / file
    if not src.exists():
        return ""
    try:
        text = src.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ""
    includes = [l.strip() for l in text.splitlines() if l.strip().startswith('#include')]
    return '\n'.join(includes[:20])  # cap at 20 includes


def _build_prompt(finding_dict: dict, source_context: str, includes: str) -> list[dict]:
    """Build system + user messages for PoC generation."""
    system = (
        "You are a security researcher writing PoC (Proof of Concept) code for "
        "OpenHarmony C/C++ vulnerabilities. Given a finding description and the "
        "surrounding source code, write a complete compilable C program that "
        "triggers the vulnerability. Rules:\n"
        "1. Write ONLY C code inside a single markdown code block.\n"
        "2. Include all necessary #include headers.\n"
        "3. Define any needed struct/typedef stubs at the top.\n"
        "4. The main() function must actually call the vulnerable function "
        "with inputs that trigger the bug (not just print a message).\n"
        "5. Add a comment at the top with: CVE/CWE, file:line, trigger description.\n"
        "6. If the function requires specific setup (e.g., network connection, "
        "IPC channel), simulate or stub the minimum needed.\n"
        "7. Return the code block only, no explanation outside it.\n"
        "8. Compile target: Linux x86_64 with gcc -fsanitize=address.\n"
    )

    user = (
        f"## Vulnerability Finding\n"
        f"Pattern: {finding_dict.get('pattern', 'unknown')}\n"
        f"CWE: {finding_dict.get('cwe', 'unknown')}\n"
        f"Severity: {finding_dict.get('severity', 'unknown')}\n"
        f"File: {finding_dict.get('file', 'unknown')}\n"
        f"Line: {finding_dict.get('line', 0)}\n"
        f"Function: {finding_dict.get('function', 'unknown')}\n"
        f"Struct/Type: {finding_dict.get('struct_type', 'N/A')}\n"
        f"Description: {finding_dict.get('description', '')}\n"
        f"Trigger hint: {finding_dict.get('trigger_hint', '')}\n"
        f"\n## Source Code Context\n"
        f"```c\n{source_context}\n```\n"
        f"\n## Includes from source\n"
        f"```c\n{includes}\n```\n"
        f"\nWrite a complete C PoC that triggers this vulnerability. "
        f"The code should compile standalone (with stub types if needed) "
        f"and call the vulnerable function with malicious input."
    )

    return [
        {'role': 'system', 'content': system},
        {'role': 'user', 'content': user},
    ]


def _extract_code_block(response_text: str) -> str | None:
    """Extract C code from LLM response (markdown code block or raw code)."""
    # Try markdown code block
    blocks = re.findall(r'```(?:c|cpp|C)?\s*\n(.*?)```', response_text, re.DOTALL)
    if blocks:
        return blocks[0].strip()
    # Try raw code (starts with #include or contains main)
    if '#include' in response_text and ('int main' in response_text or 'void ' in response_text):
        return response_text.strip()
    return None


def _validate_poc(code: str, finding_dict: dict) -> tuple[bool, str]:
    """Basic validation: does the PoC reference the right function/pattern?"""
    if not code or len(code) < 25:
        return False, "too_short"
    if 'int main' not in code and 'void main' not in code:
        return False, "no_main_function"
    if '#include' not in code:
        return False, "no_includes"
    func = finding_dict.get('function', '')
    if func and func not in code and len(func) > 3:
        # Function name should appear (unless it's a very common name)
        if func not in ('main', 'test', 'process', 'init', 'handle'):
            return False, f"target_function_{func}_not_referenced"
    return True, "ok"


def generate_poc_llm(finding_dict: dict, source_root: Path, *,
                      api_key: str | None = None,
                      model: str = 'glm-5.3',
                      base_url: str = 'https://api.z.ai/api/anthropic',
                      timeout: int = 60,
                      max_tokens: int = 2048) -> dict:
    """Generate a compilable PoC for a single finding using LLM.

    Returns dict with: {code, validated, validation_note, model, sha256}
    On failure: {code: None, error: reason}
    """
    file = finding_dict.get('file', '')
    line = finding_dict.get('line', 0)

    source_context = _extract_context(source_root, file, line)
    includes = _extract_includes(source_root, file)
    messages = _build_prompt(finding_dict, source_context, includes)

    key = runtime_key(api_key)
    try:
        result = chat_completion(
            messages,
            base_url=base_url, model=model,
            timeout=timeout, max_tokens=max_tokens,
            api_key=key, json_mode=False,
        )
    except (LlmTransportError, ValueError) as exc:
        return {'code': None, 'error': str(exc), 'model': model}

    content = result.get('content', '')
    code = _extract_code_block(content)

    if code is None:
        return {'code': None, 'error': 'no_code_block_in_response',
                'raw_response_length': len(content), 'model': model}

    valid, note = _validate_poc(code, finding_dict)

    return {
        'code': code,
        'validated': valid,
        'validation_note': note,
        'model': result.get('reported_model', model),
        'requested_model': model,
        'sha256': hashlib.sha256(code.encode('utf-8')).hexdigest(),
        'request_sha256': result.get('request_sha256', ''),
        'response_sha256': result.get('response_sha256', ''),
        'usage': result.get('usage', {}),
    }


def batch_generate(findings: list[dict], source_root: Path, output_dir: Path, *,
                   api_key: str | None = None,
                   model: str = 'glm-5.3',
                   max_items: int = MAX_FINDINGS_PER_BATCH) -> list[dict]:
    """Generate PoCs for multiple findings, saving to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []

    for i, f in enumerate(findings[:max_items]):
        finding_id = f.get('finding_id', f'unknown_{i}')
        result = generate_poc_llm(f, source_root, api_key=api_key, model=model)

        # Save PoC to file
        if result.get('code'):
            safe_id = re.sub(r'[^a-zA-Z0-9_]', '_', finding_id)[:40]
            poc_name = f"llm_poc_{safe_id}.c"
            poc_path = output_dir / poc_name
            poc_path.write_text(result['code'], encoding='utf-8')
            result['poc_file'] = poc_name

        result['finding_id'] = finding_id
        result['pattern'] = f.get('pattern', '')
        result['file'] = f.get('file', '')
        result['line'] = f.get('line', 0)
        results.append(result)

    # Save summary
    summary_path = output_dir / 'llm_poc_summary.json'
    summary = {
        'total': len(results),
        'generated': sum(1 for r in results if r.get('code')),
        'validated': sum(1 for r in results if r.get('validated')),
        'failed': sum(1 for r in results if r.get('error')),
        'model': model,
        'results': [{k: v for k, v in r.items() if k != 'code'} for r in results],
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')

    return results


def main():
    """CLI entry point."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('findings_json', type=Path,
                        help='Path to findings.json from autopilot')
    parser.add_argument('source_root', type=Path,
                        help='Root of the source tree')
    parser.add_argument('--output', type=Path, default=Path('llm_pocs'))
    parser.add_argument('--model', default='glm-5.3')
    parser.add_argument('--max', type=int, default=MAX_FINDINGS_PER_BATCH)
    parser.add_argument('--min-confidence', type=int, default=70,
                        help='Only generate PoC for findings >= this confidence')
    args = parser.parse_args()

    data = json.loads(args.findings_json.read_text(encoding='utf-8'))
    findings = [f for f in data.get('findings', [])
                if f.get('confidence', 0) >= args.min_confidence]

    print(f"Generating LLM PoCs for {len(findings)} findings "
          f"(confidence >= {args.min_confidence}, model={args.model})")

    key = os.environ.get('OSLOVELACE_API_KEY')
    if not key:
        print("ERROR: OSLOVELACE_API_KEY not set")
        return 1

    results = batch_generate(findings, args.source_root, args.output,
                              api_key=key, model=args.model, max_items=args.max)

    generated = sum(1 for r in results if r.get('code'))
    validated = sum(1 for r in results if r.get('validated'))
    print(f"Generated: {generated}/{len(results)}, Validated: {validated}/{len(results)}")
    print(f"Output: {args.output}")

    for r in results:
        status = "✅" if r.get('validated') else "❌" if r.get('error') else "⚠️"
        err = r.get('error', r.get('validation_note', ''))
        print(f"  {status} {r['finding_id'][:40]} {err}")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
