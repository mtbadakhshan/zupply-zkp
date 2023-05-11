import random
import math
import generate_sha256_gadget_tests as sha256
import sys

ZERO = [0]*sha256.HASH_BYTES

class Vertex:
	# A Vertex must always have a left child.
	def __init__(self, parent = None, left = None, right = None):
		if left == None:
			sys.exit("Left child should be specified in non-leaf vertices!")
		self.parent = parent
		self.left = left 
		self.right = right
		if right: 
			right_hash_value = right.hash_value
		else:
			right_hash_value = ZERO
		self.hash_value = sha256.H_bytes(left.hash_value + right_hash_value)

	#Leaf
	def __init__(self, parent, hash_value):
		self.hash_value = hash_value

def build_sub_path_to_leaf(leaf_value, parent, n_layer):
		if n_layer == 0: # It is at the leaf level
			return Vertex(parent, leaf_value)
		else:
			return Vertex(parent = parent, left = build_sub_path_to_leaf(leaf_value, self, n_layer - 1))

class Tree:
	def __init__(self, n_layer, first_leaf_value = ZERO):
		this.root = Vertex(
			left = build_sub_path_to_leaf(
				leaf_value = first_leaf_value, parent = None, n_layer = n_layer
				)
			)


		


def add_leaf(root, value, n_layer):
	pass 


if __name__ == '__main__':
	t = Tree(5)

# print(get_hash("0") + get_hash("1"));
# print("a".encode('utf-8'))
# print(type(get_hash("0")))

