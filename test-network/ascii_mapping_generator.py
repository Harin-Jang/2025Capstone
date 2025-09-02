import json, random, string

user_id = "user123"
ascii_keys = list(string.ascii_letters + string.digits)
mapping_table = {char: ''.join(random.choices(string.ascii_uppercase + string.digits, k=2)) for char in ascii_keys}
mapping_json_str = json.dumps(mapping_table, separators=(",", ":"))

print(f"{user_id}: {mapping_json_str}")

