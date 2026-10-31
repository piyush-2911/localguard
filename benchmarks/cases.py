"""Hand-written paired fixtures. Labels are for scoring, never model context."""


def pair(name, category, before, after, anchor, note, helper=None):
    return {"id": name, "category": category, "before": {"app.py": before},
            "after": {"app.py": after}, "anchor": anchor, "expected_file": "app.py",
            "review_note": note, **(helper or {})}


CASES = [
    pair('sql', 'sql-injection',
         'def lookup(db, name):\n    query = "SELECT id FROM users WHERE name = " + name\n    return db.execute(query).fetchall()\n',
         'def lookup(db, name):\n    return db.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchall()\n',
         '    query =', 'Assume name is attacker-controlled and db is a SQLite connection. Require parameter binding.'),
    pair('shell', 'command-injection',
         'import subprocess\ndef lookup(host):\n    return subprocess.run("nslookup " + host, shell=True, check=True)\n',
         'import ipaddress\nimport subprocess\ndef lookup(host):\n    address = str(ipaddress.ip_address(host))\n    return subprocess.run(["/usr/bin/nslookup", address], shell=False, check=True)\n',
         '    return subprocess.run', 'Attacker-controlled host reaches shell. Fix must use argument list without shell and constrain host.'),
    pair('evaluation', 'code-injection',
         'def calculate(expression):\n    return eval(expression)\n',
         'import json\ndef calculate(expression):\n    if len(expression) > 1000:\n        raise ValueError("Too long")\n    values = json.loads(expression)\n    if not isinstance(values, list) or len(values) > 10 or any(type(x) is not int for x in values):\n        raise ValueError("Invalid values")\n    return sum(values)\n',
         '    return eval', 'Assume expression is untrusted. Recommend a data parser/explicit operations, not another evaluator.'),
    pair('serialization', 'insecure-deserialization',
         'import pickle\ndef decode(payload):\n    return pickle.loads(payload)\n',
         'import json\ndef decode(payload):\n    if len(payload) > 1000:\n        raise ValueError("Too long")\n    return json.loads(payload)\n',
         '    return pickle.loads', 'Untrusted serialized payload can execute code. Data-only decoding is appropriate.'),
    pair('yaml', 'insecure-deserialization',
         'import yaml\ndef decode(payload):\n    return yaml.load(payload, Loader=yaml.Loader)\n',
         'import yaml\ndef decode(payload):\n    if len(payload) > 1000:\n        raise ValueError("Too long")\n    return yaml.safe_load(payload)\n',
         '    return yaml.load', 'Untrusted YAML must not construct arbitrary Python objects.'),
    pair('password_hash', 'weak-crypto',
         'import hashlib\ndef store_password(password):\n    return hashlib.md5(password.encode()).hexdigest()\n',
         'import hashlib\nimport os\ndef store_password(password):\n    salt = os.urandom(16)\n    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)\n    return salt, digest\n',
         '    return hashlib.md5', 'Password storage needs a salted password KDF, not plain SHA-256.'),
    pair('tls', 'insecure-network-config',
         'import requests\ndef fetch():\n    return requests.get("https://api.example.com/status", verify=False, timeout=10).json()\n',
         'import requests\ndef fetch():\n    return requests.get("https://api.example.com/status", verify=True, timeout=10).json()\n',
         '    return requests.get', 'Disabled certificate verification allows network interception; retain verification.'),
    pair('secret', 'hardcoded-secret',
         'API_PASSWORD = "service-production-password-9182"\ndef credentials():\n    return API_PASSWORD\n',
         'import os\ndef credentials():\n    return os.environ["API_PASSWORD"]\n',
         'API_PASSWORD =', 'Embedded credential versus externally supplied secret. No real credentials included.'),
    pair('traversal', 'path-traversal',
         'from pathlib import Path\nROOT = Path("/srv/public")\ndef read_file(name):\n    return (ROOT / name).read_text()\n',
         'from pathlib import Path\nROOT = Path("/srv/public")\nFILES = {"terms": ROOT / "terms.txt", "help": ROOT / "help.txt"}\ndef read_file(name):\n    return FILES[name].read_text()\n',
         '    return (ROOT / name)', 'Untrusted name may escape public root. Fixed closed map assumes server files are administrator-controlled.'),
    pair('ownership', 'access-control',
         'from flask import Flask\nfrom flask_login import login_required, current_user\nfrom storage import documents\napp = Flask(__name__)\n@app.get("/documents/<int:doc_id>")\n@login_required\ndef read_document(doc_id):\n    document = documents.get(doc_id)\n    return document.body\n',
         'from flask import Flask, abort\nfrom flask_login import login_required, current_user\nfrom storage import documents\napp = Flask(__name__)\n@app.get("/documents/<int:doc_id>")\n@login_required\ndef read_document(doc_id):\n    document = documents.get(doc_id)\n    if document.owner_id != current_user.id:\n        abort(403)\n    return document.body\n',
         '    return document.body', 'Documents are private per owner; authentication alone is insufficient. Ownership must compare trusted current_user.'),
    pair('temporary_file', 'race-condition',
         'import tempfile\ndef save_token(token):\n    name = tempfile.mktemp()\n    with open(name, "w") as stream:\n        stream.write(token)\n    return name\n',
         'import tempfile\ndef save_token(token):\n    with tempfile.NamedTemporaryFile(mode="w", delete=False) as stream:\n        stream.write(token)\n        return stream.name\n',
         '    name = tempfile.mktemp', 'Shared temporary directory: name selection and creation race. Require atomic creation.'),
    pair('helper_dispatch', 'command-injection', '', '', '    return os.system',
         'Untrusted value reaches helper shell. Fixed closed mapping allows only cwd/pid and never invokes a shell.',
         helper={"before": {"app.py": 'from worker import perform\ndef handle(value):\n    return perform(value)\n',
                            "worker.py": 'import os\ndef perform(value):\n    return os.system(value)\n'},
                 "after": {"app.py": 'from worker import perform\ndef handle(value):\n    return perform(value)\n',
                           "worker.py": 'import os\nOPERATIONS = {"cwd": os.getcwd, "pid": os.getpid}\ndef perform(value):\n    if value not in OPERATIONS:\n        raise ValueError("Unsupported operation")\n    return OPERATIONS[value]()\n'},
                 "expected_file": "worker.py"}),
]


def expected_line(case):
    matches = [i for i, line in enumerate(case['before'][case['expected_file']].splitlines(), 1)
               if line.startswith(case['anchor'])]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one anchor for {case['id']}")
    return matches[0]
