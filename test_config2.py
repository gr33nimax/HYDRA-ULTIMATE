import sys
sys.path.insert(0, '/opt/hydra')
from hydra.core.state import load_state
from hydra.plugins.registry import get
s = load_state()
a = get('amneziawg')
u = s.users[0]
print(a.generate_client_config(u, s))
