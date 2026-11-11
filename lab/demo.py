import hashlib
from .archives import samples
for name,content in samples().items():print(name,len(content),hashlib.sha256(content).hexdigest())
