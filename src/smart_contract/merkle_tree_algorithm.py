import random
import math
import generate_sha256_gadget_tests as sha256
import sys

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


def build_sub_tree(leaf_value, parent, n_layer, layer_start, id):
		v = Vertex()
		v.layer = layer_start
		v.id = id
		v.parent = parent
		print("v:", v, "v.layer: ", v.layer , "v.id: ", v.id, "v.parent: ", v.parent)
		if n_layer == 0: # It is at the leaf level
			v.hash_value = sha256.H_bytes(leaf_value)
			
		else:
			v.left = build_sub_tree(leaf_value, v, n_layer - 1, layer_start + 1, id + 1)
			v.hash_value = sha256.H_bytes(v.left.hash_value + ZERO)
			
		return v

class Tree:
	def __init__(self, n_layer, first_leaf_value = ZERO):
		self.n_layer = n_layer
		self.root = build_sub_tree([0]*sha256.BLOCK_BYTES, None, n_layer, 0, 0)
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
		v.right = build_sub_tree([0]*sha256.BLOCK_BYTES, v, counter - 1, v.layer, last_id + 1)
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
	t = Tree(3)
	print("####################################################")
	print_tree(t.root)
	t.add_leaf()
	print("######################@@@@@##############################")
	print_tree(t.root)
	t.add_leaf()
	print("######################@@@@@##############################")
	print_tree(t.root)
	t.add_leaf()
	print("######################@@@@@##############################")
	print_tree(t.root)
	t.add_leaf()
	print("######################@@@@@##############################")
	print_tree(t.root)


# print(get_hash("0") + get_hash("1"));
# print("a".encode('utf-8'))
# print(type(get_hash("0")))

