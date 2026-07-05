import sys
from pathlib import Path

# Добавим проект в PYTHONPATH
sys.path.append(str(Path(__file__).parent.parent))

from hydra.services.subscriptions.generator import generate_mieru_nekobox_link

generated = generate_mieru_nekobox_link(
    host="146.103.126.78",
    port=2015,
    protocol="TCP",
    username="tester2",
    password="ELPkOv/zxAgC4BBm993z4gdgJU4/jlAKujRLHSbHyug=",
    tag="tester2 Mieru"
)

expected = "sn://mieru?eNpjYGBgMDQx0zM0MNYzNDLTM99xn52BIcT5QklqcUlq0aa1rj4B2f5l-lUVjunOJk5OuZaWxlUm6SnpXqEm-lk5jt6lWUE-HsFJHpWl6baMQMMg-owUfDNTi742NgIATSwecg"

print(f"Generated: {generated}")
print(f"Expected:  {expected}")
print(f"MATCH:     {generated == expected}")
