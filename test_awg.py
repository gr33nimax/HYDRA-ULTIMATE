import sys
sys.path.insert(0, '/opt/hydra')
from hydra.core.state import load_state
from hydra.plugins.registry import get
s = load_state()
a = get('amneziawg')
print('Before:', a._list_peer_pubkeys())
a.configure(s)
print('After:', a._list_peer_pubkeys())
import subprocess as sp
sp.run(['awg', 'show', 'awg0'])
