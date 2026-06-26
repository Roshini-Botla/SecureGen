EXTENSION_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript (React)",
    ".tsx": "TypeScript (React)",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".cs": "C#",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".sh": "Shell",
    ".bash": "Bash",
    ".sql": "SQL",
    ".html": "HTML",
    ".xml": "XML",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".tf": "Terraform",
    ".r": "R",
}


def detect_language(ext: str) -> str:
    return EXTENSION_MAP.get(ext.lower(), "Unknown")


def count_lines(code: str) -> tuple[int, int]:
    lines = code.split("\n")
    total = len(lines)
    code_lines = sum(
        1 for line in lines
        if line.strip() and not line.strip().startswith(("#", "//", "/*", "*", "<!--", "--"))
    )
    return total, code_lines