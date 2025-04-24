import json
import os
import uuid
from datetime import datetime, timedelta
import re
from tqdm import tqdm  # Progress bar
from urllib.parse import quote, urlparse, urlunparse

# Characters commonly seen in malformed URLs
BAD_URL_CHARS = ['[', ']', '|', '\\', '^', '"', '”', '“', "'", '‘', '’', '…', '\n', '\t']

STIX_FILES_DIRECTORY = "C:\\Users\\sakis\\Desktop\\openCTI dataset\\cleaned_dataset"


def clean_and_encode_url(url):
    # Remove invisible Unicode/control characters (includes \u2028 and others)
    url = re.sub(r'[\u0000-\u001F\u007F-\u009F\u2028\u2029]', '', url)

    # Strip other common problematic characters
    for ch in BAD_URL_CHARS:
        url = url.replace(ch, '')

    # Replace percent-encoded sequences that are clearly malformed
    url = re.sub(r'%[^0-9A-Fa-f]{1,2}', '', url)

    # Clean and encode parts of the URL safely
    try:
        parts = urlparse(url)
        cleaned_url = urlunparse([
            parts.scheme,
            parts.netloc,
            quote(parts.path, safe="/"),
            parts.params,
            quote(parts.query, safe="=&"),
            quote(parts.fragment, safe="")
        ])
        return cleaned_url
    except Exception:
        return None  # Still malformed

def sanitize_urls_and_values(objects):
    for obj in objects:
        if obj.get("type") == "url":
            val = obj.get("value")
            if val:
                cleaned = clean_and_encode_url(val)
                if cleaned:
                    obj["value"] = cleaned

        refs = obj.get("external_references", [])
        for ref in refs:
            val = ref.get("url")
            if val:
                cleaned = clean_and_encode_url(val)
                if cleaned:
                    ref["url"] = cleaned

def fix_vulnerability_external_references(objects):
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

    for obj in objects:
        if obj.get("type") == "vulnerability":
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                external_id = ref.get("external_id", "")
                if cve_pattern.match(external_id):
                    ref["source_name"] = "cve"


UNWANTED_KEYS = [
    "x_opencti_id",
    "x_opencti_type",
    "x_mitre_id",
    "x_mitre_platforms",
    "x_mitre_detection",
    "x_opencti_cisa_kev"
]

def update_tlp_marking_definition(objects):
    replacement_object = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:WHITE",
        "definition": {
            "tlp": "white"
        }
    }

    for i, obj in enumerate(objects):
        if obj.get('type') == 'marking-definition' and obj.get('name') == 'TLP:CLEAR':
            objects[i] = replacement_object

def fix_relationship_times(objects):
    for obj in objects:
        if obj.get('type') == 'relationship':
            start = obj.get('start_time')
            stop = obj.get('stop_time')
            if start and stop:
                start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                stop_dt = datetime.fromisoformat(stop.replace("Z", "+00:00"))
                if stop_dt <= start_dt:
                    new_stop = start_dt + timedelta(milliseconds=1)
                    obj['stop_time'] = new_stop.isoformat(timespec="milliseconds").replace("+00:00", "Z")

def remove_unwanted_fields(objects, keys):
    for obj in objects:
        for key in keys:
            obj.pop(key, None)

def generate_new_ids(objects):
    id_map = {}
    for obj in objects:
        old_id = obj.get("id")
        obj_type = obj.get("type")
        if old_id and obj_type != "marking-definition":
            type_part = old_id.split("--")[0]
            new_id = f"{type_part}--{uuid.uuid4()}"
            id_map[old_id] = new_id
    return id_map

def apply_id_mapping_to_object(obj, id_map):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, (dict, list)):
                apply_id_mapping_to_object(value, id_map)
            elif isinstance(value, str) and value in id_map:
                obj[key] = id_map[value]
    elif isinstance(obj, list):
        for item in obj:
            apply_id_mapping_to_object(item, id_map)

def replace_object_ids(objects, id_map):
    for obj in objects:
        obj_id = obj.get("id")
        if obj_id and obj_id in id_map:
            obj["id"] = id_map[obj_id]
        apply_id_mapping_to_object(obj, id_map)

def process_stix_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    objects = data.get('objects', [])

    update_tlp_marking_definition(objects)
    fix_relationship_times(objects)
    fix_vulnerability_external_references(objects)
    # remove_unwanted_fields(objects, UNWANTED_KEYS)

    sanitize_urls_and_values(objects)
    id_map = generate_new_ids(objects)
    replace_object_ids(objects, id_map)

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def run_batch_processor(directory):
    json_files = [f for f in os.listdir(directory) if f.endswith(".json")]

    for filename in tqdm(json_files, desc="Processing STIX files"):
        filepath = os.path.join(directory, filename)
        process_stix_file(filepath)

# Run it
run_batch_processor(STIX_FILES_DIRECTORY)
