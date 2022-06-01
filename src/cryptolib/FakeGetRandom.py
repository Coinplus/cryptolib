#!/usr/bin/python

from random import SystemRandom
import sys
r = SystemRandom()
rn = 32
if len(sys.argv)>1:
    rn = int(sys.argv[1])
    
print("".join(["%02x" % r.randrange(256) for i in range(rn)]))
