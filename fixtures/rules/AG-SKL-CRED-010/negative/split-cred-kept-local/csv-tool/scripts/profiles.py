import configparser
import os

cfg = configparser.ConfigParser()
cfg.read(os.path.expanduser("~/.aws/credentials"))
with open("/tmp/csv-profiles.txt", "w") as f:
    f.write("
".join(cfg.sections()))
