import json
import os
import tempfile


def write_json_atomic(path, value, *, normalize=None):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    payload = normalize(value) if normalize else value
    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.",
        suffix=".tmp",
        dir=directory,
        text=True,
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, sort_keys=True)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            # The temporary file may already be absent.
            # Suppress this cleanup failure intentionally.
            pass
        raise
