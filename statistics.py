import os
import json
from collections import Counter, defaultdict
from tqdm import tqdm  # Progress bar

# Set your directory
STIX_FILES_DIRECTORY = "C:\\Users\\sakis\\Desktop\\openCTI dataset\\test"

# All standard STIX 2.1 types (SDO + SCO + SRO + marking + bundle)
OFFICIAL_STIX_TYPES = {
    # SDOs
    "attack-pattern", "campaign", "course-of-action", "grouping", "identity", "indicator",
    "infrastructure", "intrusion-set", "location", "malware", "malware-analysis", "note",
    "observed-data", "opinion", "report", "threat-actor", "tool", "vulnerability",
    # SCOs
    "artifact", "autonomous-system", "directory", "domain-name", "email-addr", "email-message",
    "file", "ipv4-addr", "ipv6-addr", "mac-addr", "mutex", "network-traffic", "process",
    "software", "url", "user-account", "windows-registry-key", "x509-certificate",
    # SROs
    "relationship",
    # Marking
    "marking-definition"
}

def collect_stix_statistics(directory):
    file_count = 0  # CTIPs
    object_type_counter = Counter()
    object_type_per_file = defaultdict(Counter)

    json_files = [f for f in os.listdir(directory) if f.lower().endswith(".json")]

    for filename in tqdm(json_files, desc="Processing STIX files", unit="file"):
        file_path = os.path.join(directory, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                objects = data.get("objects", [])

                file_count += 1

                for obj in objects:
                    obj_type = obj.get("type", "unknown")
                    if obj_type.startswith("x-"):  # Skip custom object types
                        continue

                    object_type_counter[obj_type] += 1
                    object_type_per_file[filename][obj_type] += 1

        except Exception as e:
            print(f"⚠️ Failed to process {filename}: {e}")

    return file_count, object_type_counter, object_type_per_file

def print_unused_stix_types(object_type_counter):
    used_types = set(object_type_counter.keys()) & OFFICIAL_STIX_TYPES
    unused_types = sorted(OFFICIAL_STIX_TYPES - used_types)

    if unused_types:
        print(f"\n🧩 Not used STIX types ({len(unused_types)} / {len(OFFICIAL_STIX_TYPES)}): " + ", ".join(unused_types))
    else:
        print("\n🎉 All 41 STIX object types are used!")

def print_statistics(file_count, object_type_counter, object_type_per_file):
    print("\n" + "=" * 60)
    print("STIX FILE STATISTICS")
    print("=" * 60)
    print(f"📦 Total CTIPs (files processed): {file_count}\n")

    used_count = len(set(object_type_counter.keys()) & OFFICIAL_STIX_TYPES)
    print(f"📊 Total STIX object type counts ({used_count} / {len(OFFICIAL_STIX_TYPES)}):")
    for obj_type, count in object_type_counter.most_common():
        print(f"  - {obj_type}: {count}")

    print_unused_stix_types(object_type_counter)

    print("\n📁 Breakdown per file (object types per file):")
    for filename, counter in object_type_per_file.items():
        print(f"\n  File: {filename}")
        for obj_type, count in counter.items():
            print(f"    - {obj_type}: {count}")

    print("=" * 60)

if __name__ == "__main__":
    file_count, object_type_counter, object_type_per_file = collect_stix_statistics(STIX_FILES_DIRECTORY)
    print_statistics(file_count, object_type_counter, object_type_per_file)
