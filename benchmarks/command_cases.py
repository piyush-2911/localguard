"""Eight command-flow pairs; imported labels never enter source context."""
from .cases import pair


def command(name, before, after, anchor, note):
    return pair(name, 'command-injection', before, after, anchor, note)


CASES = [
    command('direct', 'import os\ndef run(value):\n    return os.system(value)\n',
            'import subprocess\ndef run(value):\n    return subprocess.run(["/usr/bin/printf", "%s", value], shell=False)\n',
            '    return os.system', 'Parameter control is conditional; fixed printf uses a constant format and no shell.'),
    command('assignment', 'import os\ndef run(value):\n    command = value\n    return os.system(command)\n',
            'import os\ndef run(value):\n    command = value\n    command = "pwd"\n    return os.system(command)\n',
            '    return os.system', 'Reassignment removes parameter influence; fixed command does not contain user input.'),
    command('concatenation', 'import os\ndef run(value):\n    command = "echo " + value\n    return os.system(command)\n',
            'import os\ndef run(value):\n    if value not in ("alpha", "beta"):\n        raise ValueError("Unsupported")\n    command = "echo " + value\n    return os.system(command)\n',
            '    return os.system', 'Closed literal membership prevents shell metacharacters in this narrowly defined example.'),
    command('alias', 'from os import system as execute\ndef run(value):\n    return execute(value)\n',
            'from os import system as execute\ndef run(value):\n    if value not in ("pwd", "whoami"):\n        raise ValueError("Unsupported")\n    return execute(value)\n',
            '    return execute', 'Fixed allowed commands assume those two operations are intended and PATH is trusted.'),
    command('local_helper', 'import os\ndef execute(command):\n    return os.system(command)\ndef run(value):\n    command = "echo " + value\n    return execute(command)\n',
            'import subprocess\ndef execute(value):\n    return subprocess.run(["/usr/bin/printf", "%s", value], shell=False)\ndef run(value):\n    return execute(value)\n',
            '    return os.system', 'Track positional arguments into a directly called local function.'),
    command('helper_return', 'import os\ndef build(value):\n    return "echo " + value\ndef run(value):\n    command = build(value)\n    return os.system(command)\n',
            'import os\ndef build(value):\n    return "pwd"\ndef run(value):\n    command = build(value)\n    return os.system(command)\n',
            '    return os.system', 'Return value of helper influences command; fixed helper returns a constant.'),
    command('guard_then_overwrite', 'import os\ndef run(value, replacement):\n    if value not in ("pwd", "whoami"):\n        raise ValueError("Unsupported")\n    value = replacement\n    return os.system(value)\n',
            'import os\ndef run(value, replacement):\n    value = replacement\n    if value not in ("pwd", "whoami"):\n        raise ValueError("Unsupported")\n    return os.system(value)\n',
            '    return os.system', 'Guard must apply to the value reaching the sink, not a value overwritten earlier.'),
    pair('cross_file', 'command-injection', '', '', '    return os.system',
         'Same caller; unsafe helper invokes shell, repaired helper dispatches only a fixed operation map.',
         helper={'before': {'app.py': 'from worker import execute\ndef run(value):\n    return execute(value)\n',
                            'worker.py': 'import os\ndef execute(value):\n    return os.system(value)\n'},
                 'after': {'app.py': 'from worker import execute\ndef run(value):\n    return execute(value)\n',
                           'worker.py': 'import os\nOPERATIONS = {"cwd": os.getcwd, "pid": os.getpid}\ndef execute(value):\n    if value not in OPERATIONS:\n        raise ValueError("Unsupported")\n    return OPERATIONS[value]()\n'},
                 'expected_file': 'worker.py'}),
]
