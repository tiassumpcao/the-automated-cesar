
from sets import Set
from java.awt import Color as Color

from com.google.security.zynamics.binnavi.API.helpers import MessageBox as MessageBox
from com.google.security.zynamics.binnavi.API.helpers import GraphAlgorithms as GraphAlgorithms

from com.google.security.zynamics.binnavi.API.disassembly import ViewGraphHelpers
from com.google.security.zynamics.binnavi.API.disassembly import Address
from com.google.security.zynamics.binnavi.API.disassembly import EdgeType as EdgeType
from com.google.security.zynamics.binnavi.API.disassembly import ViewGraphHelpers as ViewGraphHelpers
from com.google.security.zynamics.binnavi.API.disassembly import CouldntSaveDataException as CouldntSaveDataException



class ControlFlowEx:
	"""This class extends the ControlFlow class."""
	def __init__(self, view, tagManager, showDominatorTree=False):
		self.view = view
		self.graph = self.view.graph
		self.children_map = {}
		self.loops = {}
		self.loop_headers = {}
		self.loop_nodes = {}
		self.loops_degree = {}
		self.loop_addresses = Set()

		self.tagManager = tagManager

		dominator_view = self.create_dominator_view(True)

		if showDominatorTree == True:
			dominator_view2d = navi.showInWindow(cf.window, dominator_view)
			dominator_view2d.doHierarchicalLayout()

	class Monotonous:
		"""Simple monotone class."""
		def __init__(self):
			self.visited = Set()

		def up_walker(self, supremum, infimum):
			"""Simple graph up-walker."""
			self.visited.add(infimum.address)
			infimum.setSelected(True)
			if infimum.address == supremum.address:
					return self.visited
			for parent in infimum.parents:
				if parent.address in self.visited:
					continue
				self.up_walker(supremum, parent)
			return self.visited

		def down_walker(self, supremum, infimum):
			"""Simple graph down-walker."""
			self.visited.add(supremum.address)
			supremum.setSelected(True)
			if supremum.address == infimum.address:
				return self.visited
			for child in supremum.children:
				if child.address in self.visited:
					continue
				self.down_walker(child, infimum)
			return self.visited

	def find_root(self, nodes):
		"""Finds the root node of a view. Note that this function is a bit imprecise
		   but it should do the trick for most views."""
		for node in nodes:
			if len(node.parents) == 0:
				return node
		return nodes[0]

	def build_children_map(self):
		"""Builds a direct map between the graph and the dominator tree,
		   so we can determine back-edges by correspondence.
		   Each link connects the related node's children.
		   Each link is indexed by the correspondent node's address."""
		for node in self.graph:
			C = Set()
			for child in node.children:
				C.add(child.address)

			self.children_map[node.address] = C

	def find_natural_loops(self, dominator_graph):
		"""Finds the natural loops in the given CFG.
		   Each found loop is added to a loop dictionary indexed by its header.
		   Each entry is an ordered pair of Edge<source, target>."""
		if self.children_map == {}:
			self.build_children_map()

		# edge n -> h, such that h dominates n
		for node in dominator_graph:
			# self-loop
			if node.address in self.children_map[node.address]:
				source = node
				target = node
				self.loop_headers[source.address] = target.address
				self.loops[source.address] = [source.address, target.address]

			predecessors = GraphAlgorithms.getPredecessors(node)
			for predecessor in predecessors:
				if predecessor.address in self.children_map[node.address]:
					source = node
					target = predecessor
					self.loop_headers[source.address] = target.address
					self.loops[source.address] = [source.address, target.address]
		return self.loops

	def find_loop_nodes(self):
		"""Connects the graph's back-edges"""
		def Tag(source, target):
			root = self.tagManager.rootTags[0]
			name = str("L<") + str(source).upper() + str(", ") + str(target).upper() + str(">")
			for child in root.children:
				if child.name == name:
					return child
			return self.tagManager.addTag(root, name)

		for Ln in self.loops.values():
			[source_address, target_address] = Ln
			source = ViewGraphHelpers.getCodeNode(self.graph, long(source_address))
			target = ViewGraphHelpers.getCodeNode(self.graph, long(target_address))

			source.addTag(Tag(source_address, target_address))
			target.addTag(Tag(source_address, target_address))

			mono = self.Monotonous()
			D = mono.up_walker(target, source)
			self.loop_nodes[source_address] = D

	def find_loop_degree(self, header, tail):
		"""Determine loop degree within a given CFG."""
		degree = 0

		# Lemma: A and B are loops, with headers a and b respectively,
		# such that a != b and b is in A
		for Ln in self.loops.values():
			[source_address, target_address] = Ln
			Lheader = target_address
			Lnodes = self.loop_nodes[source_address]

			# skip itself
			if (header == target_address) and (tail == source_address):
				continue

			# different loops sharing the same header
			if (header == Lheader):
				return degree
			if header in Lnodes:
				degree += 1
		return degree

	def color_loop_nodes(self):
		"""Color loop nodes by degree"""
		def Paint(node, degree):
			COLORS = [ Color.PINK, Color.ORANGE, Color.RED ]

			# if node is part of a higher-degree loop, already painted, leave it
			if node.color in COLORS:
				current_degree = COLORS.index(node.color)
				if current_degree >= Ldegree:
					return

			if Ldegree < 3:
				node.setColor(COLORS[Ldegree])
				node.setColor(COLORS[Ldegree])
			else:
				node.setColor(Color.RED)
				node.setColor(Color.RED)
				node.setBorderColor(Color.YELLOW)

		# loops
		for Ln in self.loops.values():
			[source_address, target_address] = Ln

			Ldegree = self.find_loop_degree(target_address, source_address)
			self.loops_degree[source_address] = Ldegree
			for node_address in self.loop_nodes[source_address]:
				node = ViewGraphHelpers.getCodeNode(self.graph, long(node_address))
				Paint(node, Ldegree)

	def determine_all_loop_addresses(self):
		"""Verify addresses pertaining to the CFG's loops."""
		for N in self.loop_nodes.itervalues():
			for node_address in N:
				node = ViewGraphHelpers.getCodeNode(self.graph, long(node_address))
				for instruction in node.instructions:
					self.loop_addresses |= Set([int(long(instruction.address))])

	def get_loop_addresses(self, loop):
		"""Retrieve <entry,exit> address pairs from the CFG's loops."""
		loop_addresses = Set()
		[source_address, target_address] = loop

		Lnodes = self.loop_nodes[source_address]
		for node_address in Lnodes:
				node = ViewGraphHelpers.getCodeNode(self.graph, long(node_address))
				for instruction in node.instructions:
					loop_addresses |= Set([int(long(instruction.address))])
		return loop_addresses

	def create_dominator_graph(self, dominator_view, root_node):
		"""Fills a given view with the nodes of a dominator tree"""
		dominator_node = dominator_view.createNode(root_node.object)

		for child in root_node.children:
			child_node = self.create_dominator_graph(dominator_view, child)
			dominator_view.createEdge(dominator_node, child_node, EdgeType.JumpUnconditional)

		return dominator_node

	def create_dominator_view(self, find_loops=False):
		"""Takes a view, calculates its dominator tree, and creates a new view
		   that shows that dominator tree."""
	
		if len(self.view.graph.nodes) == 0:
			MessageBox.showInformation("Could not create dominator tree of empty views")
			return

		# calculate the dominator tree
		dominator_tree = GraphAlgorithms.getDominatorTree(self.graph, self.find_root(self.graph.nodes))

		try:
			# create the new view
			dominator_view = self.view.container.createView("Dominator Tree: '%s'" % self.view.name, "")

			# copy all the nodes from the dominator tree into the new view
			self.create_dominator_graph(dominator_view, dominator_tree.rootNode)

			# shall we find loops
			if find_loops == True:
				self.find_natural_loops(dominator_view.graph)
				self.find_loop_nodes()
				self.color_loop_nodes()
				self.determine_all_loop_addresses()

			return dominator_view
		except CouldntSaveDataException:
			MessageBox.showInformation("Could not create the dominator tree view")
			return None


