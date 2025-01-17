import sys
import time

from BinNavi.API.helpers import MessageBox as MessageBox
from BinNavi.API.disassembly import Module as Module
from BinNavi.API.disassembly import ViewGraphHelpers as ViewGraphHelpers
from BinNavi.API.disassembly import GraphType as GraphType
from BinNavi.API.disassembly import Trace as Trace
from BinNavi.API.disassembly import TraceEvent as TraceEvent
from BinNavi.API.disassembly import ITraceListener as ITraceListener
from BinNavi.API.debug import TraceLogger as TraceLogger
from BinNavi.API.debug import BreakpointHelpers as BreakpointHelpers
from BinNavi.API.debug import ThreadState as ThreadState
from BinNavi.API.debug import IProcessListener as IProcessListener
from BinNavi.API.debug import IThreadListener as IThreadListener

sys.stdout = NAVI_CONSOLE



####### Global instances ######################################################
view = cg.view
debuggers = cf.debuggers
container = cg.container
# the specifics
debugger = debuggers[0]
###############################################################################



class ModuleEx:
	def __init__(self, module, file_base, image_base):
		self.module = module
		self.file_base = file_base
		self.image_base = image_base

		fb = self.file_base.toLong()
		ib = self.image_base.toLong()

		self.delta = (int) (fb - ib) >> 16

	def get_relocation_delta(self):
		return self.delta

	def RVA(self, va):
		base = (va >> 16)
		rva = base - self.delta
		rva <<= 16
		rva |= (va & 0x0000FFFF)

		return rva

	def VA(self, rva):
		base = (rva >> 16)
		va = base + self.delta
		va <<= 16
		va |= (rva & 0x0000FFFF)
	
		return va

class ModuleHelpersEx:
	def __init__(self, container):
		self.address_space = None
		self.modules = dict()
		self.debuggee_thread = None

		try:
			# It's a Project
			address_spaces = getattr(container, "addressSpaces")
			print "INFO: Default address space: if you want to work on a different address space, change it manually."
			self.address_space = address_spaces[0]
			# Set up modules' packages
			for module in self.address_space.modules:
				fb = module.getFilebase()
				ib = self.address_space.getImagebase(module)
				self.modules[module.name] = ModuleEx(module, fb, ib)
		except:
			# It's a Module
			fb = container.getFilebase()
			ib = container.getImagebase()
			self.modules[container.name] = ModuleEx(container, fb, ib)

	def get_module_by_name(self, name):
		return self.modules[name]

	def get_module_by_basic_block_addr(self, addr):
		pass

	def get_module_file_base(self, name):
		return self.modules[name].file_base

	def get_module_image_base(self, name):
		return self.modules[name].image_base

class TraceHelpers:
	def __init__(self, project, debugger):
		self.project = project
		self.debugger = debugger
		self.breakpoint_manager = debugger.getBreakpointManager()
		self.trace = None

	def set_trace_on_view_callgraph(self, view_graph):
		# XXX: make it dynamic!
		global MODULE

		vghlp = ViewGraphHelpers()
		bpt_list = list()
		function_nodes = vghlp.getFunctionNodes(view_graph)

		for fnode in function_nodes:
			bpt_list.append(MODULE.RVA(fnode.function.address))
########################### !!!! TEST TEST TEST !!!! ###########################
			self.breakpoint_manager.setBreakpoint(MODULE.RVA(fnode.function.address))
		trace_logger = TraceLogger(self.debugger, self.project)
		try:
			self.trace = trace_logger.start("Trace", "...", bpt_list)
		except:
			MessageBox.showInformation("Could not save trace data.")
			sys.exit(1)
################################################################################

	def set_trace_on_view_flowgraph(self, view_graph):
		# XXX: make it dynamic!
		global MODULE

		vghlp = ViewGraphHelpers()
		bpt_list = list()
		code_nodes = vghlp.getCodeNodes(view_graph)
		for cnode in code_nodes:
			bpt_list.append(MODULE.RVA(cnode.address))
		trace_logger = TraceLogger(self.debugger, self.project)
		try:
			self.trace = trace_logger.start("Trace", "...", bpt_list)
		except:
			MessageBox.showInformation("ERROR: Could not save trace data.")
			sys.exit(1)

	def set_trace_on_address_list(self, address_list):
		bpt_list = []
		reloc_delta = relocation_delta()

		for address in address_list:
			bpt_list.append(address)

		trace_logger = TraceLogger(self.debugger, self.project)
		try:
			self.trace = trace_logger.start("Trace", "...", bpt_list)
		except:
			MessageBox.showInformation("ERROR: Could not save trace data.")
			sys.exit(1)

	def add_listener(self, listener):
		print "INFO: Listening ..."
		self.trace.addListener(listener)

class ThreadHandler(IThreadListener):
	def __init__(self, thread, debugger, trace):
		print "INFO: Registering handler :: %s" % (thread)
		self.debugger = debugger
		self.breakpoint_manager = debugger.getBreakpointManager()
		self.trace = trace

	def registersChanged(self, thread):
		pass

	def stateChanged(self, thread):
		pc = thread.getCurrentAddress()
		print "INFO: STATE CHANGED => %s [%s] :: %s" % (thread.state, pc, thread)

		if thread.state == ThreadState.SUSPENDED and pc != None:
			# this should, and will, be volatile and represent the
			# module holding the debuggee code.
			global MODULE

			self.breakpoint_manager.removeBreakpoint(pc)
			self.trace.addBreakpointEvent(MODULE.VA(pc))
			self.debugger.resume(thread.threadId)

	def programCounterChanged(self, thread):
		pass

class ProcessHandler(IProcessListener):
	def __init__(self, debugger, trace):
		self.debugger = debugger
		self.process = debugger.process
		self.threads = list()
		self.handlers = dict()
		self.trace = trace

		for x in self.process.threads:
			handler = ThreadHandler(x, self.debugger, self.trace)
			x.addListener(handler)

			self.handlers[x] = handler
			self.threads.append(x)

	def attached(self, process):
		print "==> DEBUGGER ATTACHED"
		# removed ? self-restart : pass
		#self.__init__(process)

	def changedMemoryMap(self, process):
		print "==> MEMORY MAP CHANGED"

	def changedTargetInformation(self, process):
		print "==> TARGET INFO CHANGED"

	def detached(self, process):
		print "==> DEBUGGER DETACHED"
		for handler in self.handlers:
			print "INFO: Deregistering handler :: %s" % (handler)
			del handler

		# do we want to be removed at detachment?
		# shall we keep on watching.
		process.removeListener(self)

	def removedThread(self, process, x):
		# XXX: is this necessary?
		#del self.handlers[x]
		#x.removeListener(self.handlers[x])
		self.threads.remove(x)

	def addedThread(self, process, x):
		handler = ThreadHandler(x, self.debugger, self.trace)
		x.addListener(handler)
		self.handlers[x] = handler
		self.threads.append(x)
		print "==> APPENDED THREAD :: %s" % (x)

class DynamicAnalyzer:
	def __init__(self, debugger, trace):
		if debugger.isConnected() != True:
			MessageBox.showInformation("WARN: Debugger not connected.")
			sys.exit(1)

		self.debugger = debugger
		self.trace = trace
		self.breakpoint_manager = debugger.getBreakpointManager()
		self.threads = debugger.process.threads

		self.process_handler = ProcessHandler(self.debugger, self.trace)
		self.debugger.process.addListener(self.process_handler)

	def __get_debuggee_thread__(self, x, pc):
		if x < 0: return

		thread = self.threads[x]
		try:
			__pc__ = thr.getCurrentAddress()
			if pc == __pc__: return thread
		except:
			self.__get_debuggee_thread__(x - 1, pc)

	def get_debuggee_thread(self, pc):
		return self.__get_debuggee_thread__(self.threads.size() - 1, pc)

	class Analyze(ITraceListener):
		def __init__(self, analyzer):
			self.analyzer = analyzer
			self.thread = None

		def addedEvent(self, trace, event):
			# XXX: make it dynamic!
			global MODULE

			# pc is @ Dissassembly::, therefore VA.
			pc = event.address
			rva = MODULE.RVA(pc)
			# does echo breakpoints affect process execution at all?
			# it seems like "not".
			if self.thread == None:
				self.thread = self.analyzer.get_debuggee_thread(rva)

			print "<<BREAKPOINT HIT>>"
			print "    [%s] current PC (RVA) :: 0x%08x" % (trace.getName(), rva.toLong())
			print "    [%s] current PC (VA)  :: 0x%08x" % (trace.getName(), pc.toLong())
			print ""

		def changedDescription(self, trace, description):
			pass
		def changedName(self, trace, name):
			pass


###############################################################################
############## MAIN
###############################################################################

# XXX:	this should be dynamic in future -- we should be able to find out,
#		be it a multi-module 'Project' or a single-instance ('Module'), which
#		module we are dealing with.
module_helpers = ModuleHelpersEx(container)
MODULE = module_helpers.get_module_by_name('avcodec-51.dll')

######################## TRACING & DYN ANALYZER ################################
print "INFO: Setting up trace..."
trace_helper = TraceHelpers(container, debugger)
#trace_helper.set_trace_on_view_flowgraph(view.graph)
trace_helper.set_trace_on_view_callgraph(view.graph)

# trace based on echo breakpoints
#bpt_list = BreakpointHelpers.getEchoBreakpoints(debugger, view)
#print "[Echo Breakpoints] :: %s" % (bpt_list)

# trace based on actual breakpoints
bpt_list = BreakpointHelpers.getBreakpoints(debugger, view)
print "[Breakpoints] :: %s" % (bpt_list)

dyn_analysis = DynamicAnalyzer(debugger, trace_helper.trace)
#trace_listener = dyn_analysis.Analyze(dyn_analysis)
#trace_helper.add_listener(trace_listener)
#################################################################################

time.sleep(100)
trace_helper.trace.save()


