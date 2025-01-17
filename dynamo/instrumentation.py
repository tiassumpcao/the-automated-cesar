

__author__ = 'Tiago Assumpcao'
__license__ = '_'


import sys
import time
from struct import *

from java.awt import Color as Color

from com.google.security.zynamics.binnavi.API.helpers import MessageBox as MessageBox
from com.google.security.zynamics.binnavi.API.disassembly import Address as Address
from com.google.security.zynamics.binnavi.API.disassembly import ViewNode
from com.google.security.zynamics.binnavi.API.disassembly import FunctionType
from com.google.security.zynamics.binnavi.API.disassembly import EdgeType


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

class ProjectManager:
	def __init__(self, container, debuggerTempl):
		self.container = container
		self.address_space = None
		self.modules = dict()
		self.debugger = None
		try:
			# It's a Project
			address_spaces = getattr(container, "addressSpaces")
			print "[!] Default address space: if you want to work on a different address space, change it manually.\n\n"
			self.address_space = address_spaces[0]
			# Set up modules' packages
			for module in self.address_space.modules:
				fb = module.getFilebase()
				ib = self.address_space.getImagebase(module)
				self.modules[module.name] = ModuleEx(module, fb, ib)
			if module.debugger == None:
				print "[!] Modules have no debugger assigned. Assigning from template: " +\
					str(debuggerTempl)
				module.debuggerTemplate = debuggerTempl
			self.debugger = module.debugger
		except:
			# It's a Module
			fb = container.getFilebase()
			ib = container.getImagebase()
			self.modules[contaier.name] = ModuleEx(container, fb, ib)

	def get_moduleEx_by_name(self, name):
		return self.modules[name]

	def get_moduleEx_by_RVA(self, address):
		delta = 0xFFFF
		module = None
		for temp_module in self.modules.itervalues():
			temp_delta = (address >> 16) - (temp_module.image_base >> 16)
			if temp_delta == 0:
				return temp_module
			if (temp_delta > 0) and \
			   ((temp_module.delta == 0) or (temp_delta < temp_module.delta)):
				if temp_delta < delta:
					delta = temp_delta
					module = temp_module
		return module

	def get_moduleEx_by_VA(self, address):
		delta = 0xFFFF
		module = None
		for temp_module in self.modules.itervalues():
			temp_delta = (address >> 16) - (temp_module.file_base >> 16)
			if temp_delta == 0:
				return temp_module
			if (temp_delta > 0) and \
			   ((temp_module.delta == 0) or (temp_delta < temp_module.delta)):
				if temp_delta < delta:
					delta = temp_delta
					module = temp_module
		return module

	def get_moduleEx_file_base(self, name):
		return self.modules[name].file_base

	def get_moduleEx_image_base(self, name):
		return self.modules[name].image_base

	def VA(self, address):
		module = self.get_moduleEx_by_RVA(address)
		if module != None: return module.VA(address)

	def RVA(self, address):
		module = self.get_moduleEx_by_VA(address)
		if module != None: return module.RVA(address)

class ViewGraphHelpersEx:
	def __init__(self, navi):
		self.navi = navi
		self.view = None
		self.view2d = None

	def get_function_node(self, address):
		for node in self.graph:
			if node.function.address == address:
				return node
		return None

	def sync_view(self, console):
		self.view2d = self.navi.showInNewWindow(self.view)
		self.graph = self.view2d.view.graph
		try:
			self.view2d.doHierarchicalLayout()
		except:
			pass
		sys.stdout = console
		self.view.save()

	def append_graph_view(self, x):
		if self.view == None:
			print "[!] Creating new view..."
			self.view = project.createView("Inter-modular view", "")

		node_map = {}
		for node in x:
			new_node = self.view.createFunctionNode(node.function)
			new_node.setColor(new_node.color.YELLOW)
			node_map[node.function.address] = new_node

		for edge in x.edges:
			source = node_map[edge.source.function.address]
			target = node_map[edge.target.function.address]
			e = self.view.createEdge(source, target, EdgeType.JumpUnconditional)
			e.setVisible(True)

	def join_project_callgraphs(self, projmgr):
		if self.view == None:
			print "[!] Creating new view..."
			name = projmgr.container.name + " (Inter-modular view)"
			self.view = projmgr.container.createView(name, "")

		print "[+] Joining %s's views" % (projmgr.container.name)

		for module in projmgr.address_space.modules:
			print "    <%s>" % (module.name)
			if not module.loaded:
				module.load()
			self.append_graph_view(module.callgraph)

	def link(self, source, target):
		for child in source.children:
			if target.function.address == child.function.address:
				# Already linked
				linked = True
				return

		self.view.createEdge(source, target, EdgeType.JumpUnconditional)
		try: self.view2d.doHierarchicalLayout()
		except: pass

class Instrumentation(ViewGraphHelpersEx):
	def __init__(self, PM, view):
		self.PM = PM
		self.debugger = PM.debugger
		self.view = view
		self.graph = view.graph
		self.debuggee_thread = None
		self.word = None

		self.set_breakpoint_on_view_nodes()

	def __get_debuggee_thread__(self, x):
		if x < 0:
			print "[!] Process not suspended. Breakpoint hit?"
			return

		thread = self.debugger.process.threads[x]
		try:
			__pc__ = thread.getCurrentAddress()
			if __pc__ != None:
				self.debuggee_thread = thread
				return
	
			self.__get_debuggee_thread__(x - 1)
		except:
			self.__get_debuggee_thread__(x - 1)
	
	def get_debuggee_thread(self):
		return self.__get_debuggee_thread__(self.debugger.process.threads.size() - 1)

	def dump_memory(self, address, size):
		self.debugger.readMemory(address, size)
		memory = self.debugger.process.memory

		offset = 0
		while offset < size:
			self.word = memory.getData(long(address) + offset, 4)
			byte = unpack('<L', self.word.tostring())
			print "%X> %s" % (long(address) + offset, hex(byte[0]))
			offset += 4

	def get_data(self, address, tick=1):
		time.sleep(0.25)
		if tick >= 8:
			return None
		try:
			self.word = self.debugger.process.memory.getData(long(address), 4)
			if self.word != None:
				return
			self.get_data(address, tick + 1)
		except:
			self.get_data(address, tick + 1)

	def read_word(self, address):
		self.debugger.readMemory(address, 8)
		memory = self.debugger.process.memory
		self.get_data(address)
		byte = unpack('<L', self.word.tostring())
		return hex(byte[0])

	def function_address_search(self, address):
		print "[Inspect] :: searching for return address (%s) in function graphs...\n" % (address)
		for node in self.graph:
			if not node.function.loaded:
				print "   [!] Loading %s..." % (node.function)
				node.function.load()

			print "   [!] Searching nodes [%s]..." % (node.function)
			for x in node.function.graph:
				for i in x.instructions:
					if i.address == address:
						print "   [*] Address found in function graph.\n"
						return node
		print "\n[Inspect] :: could not find address in loaded function graphs.\n"
		return None

	def set_breakpoint_on_view_nodes(self):
#		if not self.debugger.connected:
#			print "[!] Debugger not connected: Connecting..."
#			self.debugger.connect()

		breakpoint_manager = self.debugger.getBreakpointManager()

		print "[+] Setting breakpoints"
		for node in self.graph:
			if node.function.type == FunctionType.Import:
				continue

			moduleEx = self.PM.get_moduleEx_by_VA(node.function.address)
			if moduleEx == None:
				print "[!] Cannot get module for VA: " + str(node.function.address)
				continue

			print "    <%s!%s>" % (str(node.function.address), moduleEx.module.name)

			if not breakpoint_manager.hasBreakpoint(moduleEx.module, moduleEx.RVA(node.function.address)):
				breakpoint_manager.setBreakpoint(moduleEx.module, moduleEx.RVA(node.function.address))

	def do_instrumentation(self):
		if not self.debugger.connected:
			print "[!] Debugger not connected: Connecting..."
			self.debugger.connect()
			time.sleep(0.25)
			if self.debugger.connected:
				print "[!] OK"
			else:
				print "[-] Cannot connect to debugger"
				return

		self.get_debuggee_thread()
		self.debugger.readRegisters(self.debuggee_thread.threadId)

		pc = self.debuggee_thread.registers[8].value
		sp = self.debuggee_thread.registers[6].value
		sp_address = Address(long(sp))
		pc_address = Address(self.PM.VA(long(pc)))

		print "[Inspect] :: %s (%X)" % (self.get_function_node(pc_address).function.name, long(pc))

		sp_value = self.read_word(sp_address)
		return_address = Address(self.PM.VA(long(sp_value, 16)))
		try:
			source = self.function_address_search(return_address)
			if source == None:
				FILE = open('C:/Users/tiago.assumpcao/Desktop/RAs.txt', 'a+')
				dbg = []
				dbg.append(str(sp_value))
				dbg.append(" --> ")
				dbg.append(str(self.get_function_node(pc_address).function.name))
				dbg.append("\n")
				FILE.writelines(dbg)
				FILE.close()
			# Resume thread
			self.debugger.resume(self.debuggee_thread.threadId)
		except:
			print "[Inspect] :: return address outside view graph (%X)" % (long(sp_value, 16))
			FILE = open('C:/Users/tiago.assumpcao/Desktop/RAs.txt', 'a+')
			dbg = []
			dbg.append(str(sp_value))
			dbg.append(" --> ")
			dbg.append(str(self.get_function_node(pc_address).function.name))
			dbg.append("\n")
			FILE.writelines(dbg)
			FILE.close()
			# Resume thread
			self.debugger.resume(self.debuggee_thread.threadId)
			return
		if source != None:
			target = None
			for node in self.graph:
				if pc_address == node.function.address:
					target = node
			print "[Inspect] :: call (%s -> %s)" % (source.function.name, target.function.name)
			self.link(source, target)
		# Resume thread
		self.debugger.resume(self.debuggee_thread.threadId)



