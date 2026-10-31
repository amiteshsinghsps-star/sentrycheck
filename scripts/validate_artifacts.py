"""Validate generated reports, profiles, and manifest JSON against their contracts."""
import json
from pathlib import Path
import jsonschema

root = Path(__file__).resolve().parents[1]
schema = json.loads((root / "schema/report.schema.json").read_text(encoding="utf-8"))
jsonschema.Draft202012Validator.check_schema(schema)
validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
reports = [path for directory in ["evaluation", "live-validation", "live-baselines", "live-postgres"] for path in (root / "artifacts" / directory).glob("*.report.json")]
for path in reports:
    validator.validate(json.loads(path.read_text(encoding="utf-8")))
for path in (root / "deploy").glob("*.json"):
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "apiVersion" in data and "kind" in data, path
print("Validated", len(reports), "reports and all deployment JSON documents")
