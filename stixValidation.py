import os
import sys
from io import StringIO
import contextlib
from stix2validator import validate_file, ValidationOptions, print_results
import re

def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)



STIX_FILES_DIRECTORY = "C:\\Users\\sakis\\Desktop\\openCTI dataset\\test"

def validate_stix_files():
    if not os.path.exists(STIX_FILES_DIRECTORY):
        print(f"Error: Directory '{STIX_FILES_DIRECTORY}' does not exist.")
        sys.exit(1)

    options = ValidationOptions(version="2.1", strict=True)
    json_files = []

    for root, _, files in os.walk(STIX_FILES_DIRECTORY):
        for file in files:
            if file.lower().endswith('.json'):
                json_files.append(os.path.join(root, file))

    if not json_files:
        print(f"No JSON files found in {STIX_FILES_DIRECTORY}")
        return

    valid_count = 0
    error_count = 0
    invalid_files = {}
    captured_outputs = {}

    for file_path in json_files:
        file_name = os.path.basename(file_path)
        try:
            buffer = StringIO()

            with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
                results = validate_file(file_path, options)
                print_results(results)

            temp_results = strip_ansi_codes(buffer.getvalue())
            captured_outputs[file_name] = temp_results
            error_lines = [
                line.strip() for line in temp_results.splitlines()
                if line.strip().startswith("[X]")
            ]

            if results.is_valid:
                valid_count += 1
            else:
                invalid_files[file_name] = error_lines

        except Exception as e:
            error_count += 1
            invalid_files[file_name] = [f"Processing error: {str(e)}"]

    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY:")
    print(f"  Total files processed: {len(json_files)}")
    print(f"  Valid STIX 2.1 documents: {valid_count}")
    print(f"  Invalid STIX 2.1 documents: {len(invalid_files)}")
    print(f"  Files with processing errors: {error_count}")
    print("=" * 60)

    if invalid_files:
        print("\nINVALID FILES:")
        for file_name, errors in invalid_files.items():
            print(f"  File: {file_name}")
            print("    Errors:")
            if errors:
                for error in errors:
                    print(f"      {error}")
            else:
                print("      No specific errors detected")
            print()
    print("=" * 60)


if __name__ == "__main__":
    validate_stix_files()