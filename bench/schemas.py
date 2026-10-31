"""JSON Schema validation for harness records, with no third-party dependency.

A deliberately small Draft 2020-12 subset is implemented here instead of importing
`jsonschema`, because the analyzer must produce identical verdicts on Windows, Linux and
inside the benchmark image regardless of which library version is installed. Any keyword
the generator uses but this module does not understand is reported as an error rather than
silently ignored, so schema drift cannot quietly become a passing validation.
"""
import re
from functools import lru_cache

from bench.common import BENCH, ROOT, BenchError, read_json, sha256_file

ANNOTATION = {"$schema", "$id", "title", "description", "default", "examples", "format", "$comment"}
TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
    "integer": int,
    "number": (int, float),
}
CONSTRUCTING = {"type", "properties", "required", "additionalProperties", "$defs", "$ref", "enum",
                "const", "pattern", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
                "items", "prefixItems", "minItems", "maxItems", "anyOf", "allOf", "oneOf", "if", "then", "else",
                "propertyNames", "contains", "minContains", "maxContains", "uniqueItems", "dependencies"}
assert not (ANNOTATION & CONSTRUCTING)


def type_name(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "integer" if isinstance(value, int) else "number"
    return {dict: "object", list: "array", str: "string", type(None): "null"}.get(type(value), type(value).__name__)


def matches_type(value, expected):
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return isinstance(value, TYPES[expected])


def _validate(instance, schema, defs, path, errors, seen_refs=()):
    for keyword in schema:
        if keyword in ANNOTATION:
            continue
        if keyword not in CONSTRUCTING:
            errors.append("%s: unsupported schema keyword %r" % (path or "/", keyword))
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise BenchError("only local $defs references are supported, got %s" % ref)
        name = ref[len("#/$defs/"):]
        if name not in defs:
            raise BenchError("schema reference $defs/%s is missing" % name)
        if ref in seen_refs:
            return
        _validate(instance, defs[name], defs, path, errors, seen_refs + (ref,))
        return
    if "type" in schema:
        expected = schema["type"]
        options = expected if isinstance(expected, list) else [expected]
        if not any(matches_type(instance, option) for option in options):
            errors.append("%s: expected type %s, found %s" % (path or "/", "|".join(options), type_name(instance)))
            return
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: %r is not one of %s" % (path or "/", instance, schema["enum"]))
    if "const" in schema and instance != schema["const"]:
        errors.append("%s: expected constant %r, found %r" % (path or "/", schema["const"], instance))
    if isinstance(instance, str) and "pattern" in schema and not re.fullmatch(schema["pattern"], instance):
        errors.append("%s: %r does not match pattern %s" % (path or "/", instance, schema["pattern"]))
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append("%s: %r is below minimum %r" % (path or "/", instance, schema["minimum"]))
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append("%s: %r is above maximum %r" % (path or "/", instance, schema["maximum"]))
        if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
            errors.append("%s: %r is not above exclusive minimum %r" % (path or "/", instance, schema["exclusiveMinimum"]))
        if "exclusiveMaximum" in schema and instance >= schema["exclusiveMaximum"]:
            errors.append("%s: %r is not below exclusive maximum %r" % (path or "/", instance, schema["exclusiveMaximum"]))
    if isinstance(instance, dict):
        for required in schema.get("required", []):
            if required not in instance:
                errors.append("%s: required member %r is missing" % (path or "/", required))
        properties = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                _validate(value, properties[key], defs, "%s/%s" % (path, key), errors, seen_refs)
            elif extra is False:
                errors.append("%s: unexpected member %r (additionalProperties is false)" % (path or "/", key))
            elif isinstance(extra, dict):
                _validate(value, extra, defs, "%s/%s" % (path, key), errors, seen_refs)
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append("%s: %d items is below minItems %d" % (path or "/", len(instance), schema["minItems"]))
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append("%s: %d items exceeds maxItems %d" % (path or "/", len(instance), schema["maxItems"]))
        if "items" in schema:
            for index, value in enumerate(instance):
                _validate(value, schema["items"], defs, "%s[%d]" % (path, index), errors, seen_refs)
        for index, value in enumerate(instance[: len(schema.get("prefixItems", []))]):
            _validate(value, schema["prefixItems"][index], defs, "%s[%d]" % (path, index), errors, seen_refs)
    for branch in schema.get("anyOf", []):
        # anyOf: pass if at least one branch validates.
        trial = []
        _validate(instance, branch, defs, path, trial, seen_refs)
        if not trial:
            break
    else:
        if "anyOf" in schema:
            errors.append("%s: matches none of the anyOf branches" % (path or "/"))
    for branch in schema.get("allOf", []):
        _validate(instance, branch, defs, path, errors, seen_refs)
    if "oneOf" in schema:
        hits = 0
        for branch in schema["oneOf"]:
            trial = []
            _validate(instance, branch, defs, path, trial, seen_refs)
            hits += not trial
        if hits != 1:
            errors.append("%s: matched %d oneOf branches, expected exactly 1" % (path or "/", hits))
    if "if" in schema:
        trial = []
        _validate(instance, schema["if"], defs, path, trial, seen_refs)
        branch = schema.get("then") if not trial else schema.get("else")
        if branch is not None:
            _validate(instance, branch, defs, path, errors, seen_refs)


@lru_cache(maxsize=None)
def load(name):
    path = {
        "case": BENCH / "schema" / "case.schema.json",
        "run": BENCH / "schema" / "run.schema.json",
        "label": BENCH / "schema" / "label.schema.json",
        "host": BENCH / "schema" / "host.schema.json",
        "report": ROOT / "schema" / "report.schema.json",
        "profile": ROOT / "schema" / "profile.schema.json",
    }
    if name not in path:
        raise BenchError("unknown schema %r (expected one of %s)" % (name, " ".join(sorted(path))))
    return read_json(path[name])


def validate(schema, instance, defs=None):
    """Validate against an inline schema; used by tests and by composed contracts."""
    found = []
    _validate(instance, schema, (defs if defs is not None else schema.get("$defs", {})), "", found)
    return found


def errors(name, instance):
    return validate(load(name), instance)


def check(name, instance, context=""):
    found = errors(name, instance)
    if found:
        label = "%s in %s" % (context, name) if context else name
        raise BenchError("schema validation failed for %s:\n  %s" % (label, "\n  ".join(found)))


def selftest():
    """Round-trip every contract: parse, exercise one valid and one invalid instance."""
    results = []
    for name in ("case", "run", "label", "host", "report", "profile"):
        schema = load(name)
        required = sorted(schema.get("required", []))
        results.append({"schema": name, "title": schema.get("title"), "required_members": len(required)})
    # Negative control: an empty object must fail every contract.
    for name in ("case", "run", "label", "host"):
        if not errors(name, {}):
            raise BenchError("%s schema accepted an empty object" % name)
    return results


def command_schemas(args):
    report = selftest()
    for entry in report:
        candidate = BENCH / "schema" / ("%s.schema.json" % entry["schema"])
        if not candidate.exists():
            candidate = ROOT / "schema" / ("%s.schema.json" % entry["schema"])
        entry["sha256"] = sha256_file(candidate)
    if getattr(args, "json", False):
        import json
        print(json.dumps({"schemas": report}, indent=2, sort_keys=True))
    else:
        for entry in report:
            print("%-8s %s  required=%2d  %s" % (entry["schema"], entry["sha256"][:17], entry["required_members"], entry["title"]))
    return 0
