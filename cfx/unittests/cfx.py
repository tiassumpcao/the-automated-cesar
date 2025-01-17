import sys
import os
import time

import binnavi

from binnavi.reil.dietreil import Transform
from binnavi.cfx.cfx import ControlFlowEx

from java.awt import Color as Color
from com.google.security.zynamics.binnavi.API.reil.mono import InstructionGraph


#######################################
DATABASE = dbs.databases[0]           #
TAG_MANAGER = DATABASE.nodeTagManager #
#######################################


print ""
print ""
print ""
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%% S T A R T %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%", " %s " % (time.ctime()), "%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print ""

# Build the extended control flow graph
cfx = ControlFlowEx(cg.view, TAG_MANAGER)

print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% E N D %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%", " %s " % (time.ctime()), "%%%%%%%%%%%%%%%%%%%%%%"
print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
print ""

