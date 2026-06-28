import sys
sys.path.insert(0, '/opt/hydra')
from hydra.plugins.registry import get
from hydra.core.state import load_state
s = load_state()
a = get('amneziawg')
# Resync to generate and save PSK
a.configure(s)
u = s.users[0]
c = a.generate_client_config(u, s)
print(c)
