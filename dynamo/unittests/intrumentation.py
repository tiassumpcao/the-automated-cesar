import sys
import os

import binnavi
from binnavi.dynamo.instrumentation import ModuleEx
from binnavi.dynamo.instrumentation import ProjectManager
from binnavi.dynamo.instrumentation import ViewGraphHelpersEx
from binnavi.dynamo.instrumentation import Instrumentation

from com.google.security.zynamics.binnavi.API.debug import Debugger


####### Project name ##########################################################
DATABASE = "BinNavi"
PROJECT = "ClamAV"
DEBUGGER = "ubuntu32"
####### Global instances ######################################################
database = None
project = None
debugger = None
tagmgr = None
###############################################################################


##############################################################################
############## MAIN
##############################################################################
for database in dbs.databases:
    if DATABASE in database.name:
        break

if database == None:
    print "[-] Cannot find database"
    sys.exit(1)

for project in database.projects:
	if PROJECT in project.name:
		break

if project == None:
	print "[-] Cannot find project"
	sys.exit(1)

if not project.loaded:
	project.load()

for debuggerTempl in project.debuggerTemplates:
	if DEBUGGER in debuggerTempl.name:
		break
if debuggerTempl == None:
	print "[-] Cannot find debugger template"

PM = ProjectManager(project, debuggerTempl)
vghlp = ViewGraphHelpersEx(navi)
vghlp.join_project_callgraphs(PM) 
vghlp.sync_view(SCRIPT_CONSOLE)

if PM.debugger == None:
	print "[-] Cannot find assign a debugger. Add it manually."
	sys.exit(1)

I = Instrumentation(PM, vghlp.view)
I.do_instrumentation()

