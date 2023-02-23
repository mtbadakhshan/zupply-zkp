#!/usr/bin/env python
##
# @author     This file is part of libsnark, developed by SCIPR Lab
#             and contributors (see AUTHORS).
# @copyright  MIT license (see LICENSE file)

import random
import math
import pypy_sha256 # PyPy's implementation of SHA256 compression function; see copyright and authorship notice within.

BLOCK_LEN = 512
BLOCK_BYTES = BLOCK_LEN // 8
HASH_LEN = 256
HASH_BYTES = HASH_LEN // 8

def gen_random_bytes(n):
    return [random.randint(0, 255) for i in range(n)]

def words_to_bytes(arr):
    return sum(([x >> 24, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff] for x in arr), [])

def bytes_to_words(arr):
    l = len(arr)
    assert l % 4 == 0
    return [(arr[i*4 + 3] << 24) + (arr[i*4+2] << 16) + (arr[i*4+1] << 8) + arr[i*4] for i in range(l//4)]

def cpp_val(s, log_radix=32):
    if log_radix == 8:
        hexfmt = '0x%02x'
    elif log_radix == 32:
        hexfmt = '0x%08x'
        s = bytes_to_words(s)
    else:
        raise
    return 'libff::int_list_to_bits({%s}, %d)' % (', '.join(hexfmt % x for x in s), log_radix)

def H_bytes(x):
    assert len(x) == BLOCK_BYTES
    state = pypy_sha256.sha_init()
    state['data'] = words_to_bytes(bytes_to_words(x))
    pypy_sha256.sha_transform(state)
    return words_to_bytes(bytes_to_words(words_to_bytes(state['digest'])))

def generate_sha256_gadget_tests():
    left = gen_random_bytes(HASH_BYTES)
    right = gen_random_bytes(HASH_BYTES)
    hash = H_bytes(left + right)

    print("const libff::bit_vector left_bv = %s;" % cpp_val(left))
    print("const libff::bit_vector right_bv = %s;" % cpp_val(right))
    print("const libff::bit_vector hash_bv = %s;" % cpp_val(hash))

def all_0s_hash():
    h = H_bytes([0]*BLOCK_BYTES)
    print(h)
    print("const libff::bit_vector hash_bv = %s;" % cpp_val(h))

def generate_merkle_tree(leaves):
    n_layers = math.ceil(math.log2(len(leaves))) 
    tree = {}
    ### Adding leaves to the tree
    tree["layer 0"] = []
    for leaf in leaves:
        tree["layer 0"].append(leaf)
    for i in range(n_layers ):
        layer = tree["layer %d" % i]
        tree["layer %d" % (i+1)] = []
        for j in range(len(layer) // 2 ):
            h = H_bytes(layer[2*j] + layer[2*j + 1])
            tree["layer %d" % (i+1)].append(h)
    return tree

def make_merkle_proof(tree, key):
    path = []
    ### starts from layer 0 (leaves) to layer n (root)
    for layer in tree:
        # print(layer)
        # print(tree[layer])
        # print("key = ", key , " | len(tree[layer]) = ", len(tree[layer]))
        if len(tree[layer]) == 1:
            path.append(['root', tree[layer][0]])
            return path
        if(key % 2):
            path.append(['left' ,tree[layer][key - 1]])
        else:
            path.append(['right', tree[layer][key + 1]])
        key = key // 2
    return 'Error'

def verify_merkle_proof(leaf, path):
    for i in range(len(path)):
        if(path[i][0] == 'right'):
            leaf = H_bytes(leaf + path[i][1])
        elif(path[i][0] == 'left'):
            leaf = H_bytes(path[i][1] + leaf)
        else:
            return leaf == path[i][1]






if __name__ == '__main__':
    # random.seed(0) # for reproducibility
    # all_0s_hash()
    N = 8
    leaves = [[0]*HASH_BYTES for _ in range(N)]
    ### Initializing with key values
    for i in range(N):
        leaves[i][-1] = i
    print(len(leaves[0]))
    tree = generate_merkle_tree(leaves)
    print(tree)
    path = make_merkle_proof(tree, 2)
    print("path : ", path)

    print("Verify: ", verify_merkle_proof(leaves[2], path))