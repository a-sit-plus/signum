"""Reject handwritten Kotlin examples and references outside named test-source regions."""

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FENCE = re.compile(r"^\s*(`{3,}|~{3,})(\S*)(.*)$")
REFERENCE = re.compile(r'^\s*--8<--\s+"([^"\n]+)"\s*$')


def reference_error(root, reference):
    path, separator, region = reference.rpartition(":")
    if not separator or not region:
        return "Kotlin snippets need a named region"
    source = (root / path).resolve()
    if not source.is_relative_to(root.resolve()):
        return "snippet leaves the repository"
    if source.suffix != ".kt" or "/examples/" not in path:
        return "Kotlin snippets must come from the examples package"
    if not any(f"/src/{kind}/kotlin/" in path for kind in (
        "jvmTest", "iosTest", "androidDeviceTest", "test",
    )):
        return "Kotlin snippets must come from test sources"
    if "/src/test/" in path and not path.startswith("docs/legacy-examples/"):
        return "plain JVM snippets must come from the isolated legacy project"
    if not source.is_file():
        return f"missing source: {path}"
    content = source.read_text()
    if not re.search(r"^package\s+[\w.]*\.examples(?:\.[\w.]+)?\s*$", content, re.M):
        return "source must declare a separate examples package"
    start = f"--8<-- [start:{region}]"
    end = f"--8<-- [end:{region}]"
    if content.count(start) != 1 or content.count(end) != 1:
        return f"missing or duplicate region: {region}"
    if content.index(start) >= content.index(end):
        return f"reversed region: {region}"
    if not content[content.index(start) + len(start):content.index(end)].rsplit("\n", 1)[0].strip():
        return f"empty region: {region}"
    return None


def page_errors(root, page):
    errors = []
    fence = None
    kotlin = False
    snippets = 0
    for number, line in enumerate(page.read_text().splitlines(), 1):
        match = FENCE.match(line)
        if match and fence is None:
            fence = match[1]
            kotlin = match[2].lower() in ("kotlin", "kt", "kts")
            snippets = 0
        elif fence and line.strip() == fence:
            if kotlin and not snippets:
                errors.append(f"{page}:{number}: empty Kotlin example")
            fence = None
            kotlin = False
        elif kotlin and line.strip():
            reference = REFERENCE.fullmatch(line)
            error = reference_error(root, reference[1]) if reference else "handwritten Kotlin example"
            if error:
                errors.append(f"{page}:{number}: {error}")
            snippets += 1
    if kotlin:
        errors.append(f"{page}: unclosed Kotlin fence")
    return errors


def self_test():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "module/src/jvmTest/kotlin/at/asitplus/signum/examples/Example.kt"
        source.parent.mkdir(parents=True)
        source.write_text("package at.asitplus.signum.examples\n// --8<-- [start:demo]\nval n = 1\n// --8<-- [end:demo]\n")
        path = source.relative_to(root).as_posix()
        page = root / "example.md"
        page.write_text(f'```kotlin\n--8<-- "{path}:demo"\n```\n')
        assert page_errors(root, page) == []
        assert reference_error(root, f"{path}:missing")
        assert reference_error(root, "../outside.kt:demo")
        source.write_text(source.read_text().replace("[end:demo]", "[end:missing]"))
        assert page_errors(root, page)
        page.write_text("```kotlin\nval n = 1\n```\n")
        assert page_errors(root, page)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    errors = []
    for page in sorted((ROOT / "docs/docs").rglob("*.md")):
        if "dokka" not in page.relative_to(ROOT / "docs/docs").parts:
            errors.extend(page_errors(ROOT, page))
    if errors:
        sys.exit("\n".join(errors))
    print("Documentation snippets reference named examples in test sources.")
