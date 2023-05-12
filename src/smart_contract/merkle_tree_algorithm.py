import random
import math
import generate_sha256_gadget_tests as sha256
import sys
import networkx as nx
from matplotlib import pyplot as plt
import pydot
# from networkx.drawing.nx_pydot import graphviz_layout


ZERO = [0]*sha256.HASH_BYTES

class Vertex:
	def __init__(self):
		self.layer = None
		self.id = None
		self.parent = None
		self.left = None
		self.right = None
		self.hash_value = None

	def print(self):
		print("#### id = %d ####" %self.id)
		print(self)
		print("parent: ", self.parent)
		print("left: ", self.left)
		print("right: ", self.right)
		print(self.hash_value)
		print("####################################################")


def build_sub_tree(leaf_value, parent, n_layer, layer_start, id, graph):
		v = Vertex()
		v.layer = layer_start
		v.id = id
		v.parent = parent
		if(parent):
			graph.add_edges_from([(parent.id, v.id)])
		print("v:", v, "v.layer: ", v.layer , "v.id: ", v.id, "v.parent: ", v.parent)
		if n_layer == 0: # It is at the leaf level
			v.hash_value = sha256.H_bytes(leaf_value)
			
		else:
			v.left = build_sub_tree(leaf_value, v, n_layer - 1, layer_start + 1, id + 1, graph)
			v.hash_value = sha256.H_bytes(v.left.hash_value + ZERO)
			
		return v

class Tree:
	def __init__(self, n_layer, first_leaf_value = ZERO):
		self.n_layer = n_layer
		self.graph = nx.DiGraph()
		self.root = build_sub_tree([0]*sha256.BLOCK_BYTES, None, n_layer, 0, 0, self.graph)
		print("root:", self.root, "root.layer: ", self.root.layer )


	def add_leaf(self, leaf_value = ZERO):
		v = self.root
		
		while(v.left):
			if(v.right):
				v = v.right
			else:
				v = v.left

		# We will have the last added leaf here: v
		last_id = v.id
		v = v.parent
		counter = 1
		while(v.right):
			v = v.parent
			if (v == None):
				sys.exit("The tree is full!")
			counter = counter + 1
		v.right = build_sub_tree([0]*sha256.BLOCK_BYTES, v, counter - 1, v.layer, last_id + 1, self.graph)
		v.hash_value = sha256.H_bytes(v.left.hash_value + v.right.hash_value)

		# updating preceding vertices
		while(v.parent != None):
			v = v.parent
			if(v.right):
				right_hash_value = v.right.hash_value
			else:
				right_hash_value = ZERO
			print(v)		
			v.hash_value = sha256.H_bytes(v.left.hash_value + right_hash_value)
			



def print_tree(v):
	v.print()
	if(v.left):
		print_tree(v.left)
	if (v.right):
		print_tree(v.right)




if __name__ == '__main__':
	# root = Vertex()
	t = Tree(5)

	n_leaves = 1
	while True:
		pos = nx.nx_agraph.graphviz_layout(t.graph, prog="dot", args="")
		nx.draw(t.graph, pos, with_labels=True)
		plt.rcParams['figure.figsize'] = [16, 4]
		plt.savefig("figures/mht_%d.png" %n_leaves)
		plt.clf()
		plt.cla()
		plt.close()
		t.add_leaf()
		n_leaves += 1


