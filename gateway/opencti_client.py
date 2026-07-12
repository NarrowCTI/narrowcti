from copy import deepcopy

from pycti import OpenCTIApiClient


ABOUT_QUERY = """
query NarrowCTIPlatformVersion {
  about {
    version
  }
}
"""

LEGACY_OPENCTI_PREFIXES = ("6.9.",)
PYCTI7_INPUT_FIELDS = frozenset(
    {
        "AIPrompt",
        "ICCID",
        "IMEI",
        "IMSI",
        "embedded",
        "files",
        "filesMarkings",
        "noTriggerImport",
        "upsertOperations",
    }
)
PYCTI7_QUERY_INPUTS = (
    "AIPrompt",
    "ICCID",
    "IMEI",
    "IMSI",
    "upsertOperations",
)


class OpenCTICompatibilityError(ValueError):
    pass


def _is_empty_compatibility_value(value):
    return value is None or value is False or value == "" or value == [] or value == {}


def sanitize_legacy_variables(value, path="variables"):
    """Remove pycti 7 input fields unsupported by OpenCTI 6.9.

    NarrowCTI does not use these fields today. Non-empty values fail closed so
    compatibility handling can never discard an attachment or upsert request.
    """
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            item_path = f"{path}.{key}"
            if key in PYCTI7_INPUT_FIELDS:
                if not _is_empty_compatibility_value(item):
                    raise OpenCTICompatibilityError(
                        f"OpenCTI 6.9 compatibility cannot discard {item_path}"
                    )
                continue
            sanitized[key] = sanitize_legacy_variables(item, item_path)
        return sanitized
    if isinstance(value, list):
        return [
            sanitize_legacy_variables(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    return deepcopy(value)


def sanitize_legacy_query(query):
    """Remove pycti 7 observable inputs absent from the OpenCTI 6.9 schema."""
    lines = []
    for line in str(query or "").splitlines(keepends=True):
        if any(
            f"${input_name}:" in line or f"{input_name}: ${input_name}" in line
            for input_name in PYCTI7_QUERY_INPUTS
        ):
            continue
        lines.append(line)
    return "".join(lines)


class NarrowCTIOpenCTIApiClient(OpenCTIApiClient):
    """OpenCTI client with an explicit, version-scoped 6.9 compatibility boundary."""

    platform_version = ""

    def health_check(self):
        try:
            result = OpenCTIApiClient.query(self, ABOUT_QUERY)
            self.platform_version = str(
                ((result.get("data") or {}).get("about") or {}).get("version") or ""
            ).strip()
            return bool(self.platform_version)
        except Exception as exc:  # pycti health checks intentionally return a bool
            self.app_logger.error(str(exc))
            return False

    @property
    def uses_legacy_input_schema(self):
        return self.platform_version.startswith(LEGACY_OPENCTI_PREFIXES)

    def query(self, query, variables=None, disable_impersonate=False):
        query_text = query
        query_variables = variables
        if self.uses_legacy_input_schema:
            query_text = sanitize_legacy_query(query)
            if variables:
                query_variables = sanitize_legacy_variables(variables)
        return super().query(query_text, query_variables, disable_impersonate)


def build_opencti_client(opencti_url, opencti_token, **kwargs):
    return NarrowCTIOpenCTIApiClient(opencti_url, opencti_token, **kwargs)
