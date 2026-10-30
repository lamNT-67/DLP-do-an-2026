import io
import re
import zipfile

MAX_FILE_BYTES = 20 * 1024 * 1024
_OFFICE_PARTS = re.compile(r"^(word/.*\.xml|xl/sharedStrings\.xml|xl/worksheets/.*\.xml|ppt/slides/.*\.xml)$")
_TAGS = re.compile(r"<[^>]+>")


def extract_text(data, filename=""):
    """Tra ve van ban de quet. Ho tro text thuong va docx/xlsx/pptx (zip XML)."""
    if not data:
        return ""
    data = data[:MAX_FILE_BYTES]
    if data[:2] == b"PK":
        try:
            parts = []
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for n in z.namelist():
                    if _OFFICE_PARTS.match(n):
                        xml = z.read(n).decode("utf-8", errors="ignore")
                        parts.append(_TAGS.sub(" ", xml))
            if parts:
                return "\n".join(parts)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            pass
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="ignore")
    return data.decode("utf-8", errors="ignore")


def read_file_text(path):
    try:
        with open(path, "rb") as f:
            return extract_text(f.read(MAX_FILE_BYTES), path)
    except (PermissionError, FileNotFoundError, OSError):
        return ""