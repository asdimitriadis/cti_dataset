import json
import jsonschema


with open('test_file.json', 'r', encoding='utf-8') as f:
    schema = json.load(f)


try:
    ValidatorClass = jsonschema.validators.validator_for(schema)
    ValidatorClass.check_schema(schema)
    print("Schema is valid.")
except jsonschema.exceptions.SchemaError as e:
    print("Schema is invalid:", e)