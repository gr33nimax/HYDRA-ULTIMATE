import sys, hashlib, base64, subprocess
sys.path.insert(0, '/opt/hydra')
from hydra.core.state import load_state
from hydra.plugins.registry import get

s = load_state()
a = get('amneziawg')
u = s.users[0]
print('User:', u.email, 'UUID:', u.uuid)

h = hashlib.sha256(u.uuid.encode()).digest()
priv = base64.b64encode(h[:32]).decode()
pub = subprocess.run(['awg', 'pubkey'], input=priv, capture_output=True, text=True).stdout.strip()
print('Derived priv:', priv)
print('Derived pub:', pub)

# Try adding via awg CLI directly
psk = subprocess.run(['awg', 'genpsk'], capture_output=True, text=True).stdout.strip()
print('PSK:', psk)

psk_file = '/tmp/psk_test'
with open(psk_file, 'w') as f:
    f.write(psk)

r = subprocess.run(['awg', 'set', 'awg0', 'peer', pub,
    'preshared-key', psk_file,
    'allowed-ips', '10.66.66.2/32'],
    capture_output=True, text=True)
print('Add result:', r.returncode, r.stderr)

subprocess.run(['awg', 'show', 'awg0'])
