import sys, os, time, threading
sys.path.insert(0, '.')

from nids import alert_store
from nids import sniffer

t = threading.Thread(target=sniffer.start, kwargs={'simulate': True}, daemon=True)
t.start()
time.sleep(15)

alerts = alert_store.get_all()
print('\n--- SMOKE TEST RESULTS ---')
print('Total alerts generated:', len(alerts))
types = {}
for a in alerts:
    key = a['type']
    types[key] = types.get(key, 0) + 1
for k, v in sorted(types.items()):
    print(' ', k + ':', v)
if len(alerts) > 0:
    print('PASS')
else:
    print('FAIL - no alerts')
