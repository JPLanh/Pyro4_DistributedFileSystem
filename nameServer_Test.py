import Pyro4
from Pyro4 import naming

with Pyro4.locateNS(host="35.212.249.77", port=26842) as ns:
    print(ns.list())            
#    ns.remove("155322617014379048702147032993762967330")
#    print(ns.list())
