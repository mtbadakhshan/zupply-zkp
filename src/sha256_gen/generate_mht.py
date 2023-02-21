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
    print(leaves)
    n_layers = math.ceil(math.log2(len(leaves)))
    print("n_layers =",  n_layers)

    # layer_size = len(leaves)
    layer = leaves
    tree = {}
    for i in range(n_layers):
        tree["layer %d" % i] = []
        for j in range(len(layer) >> 1 ):
            s1 = bytes_to_words(layer[j])
            s2 = bytes_to_words(layer[j+1])
            node1 = '%s' % (', '.join('0x%08x' % x for x in s1))
            node2 = '%s' % (', '.join('0x%08x' % x for x in s2))
            tree["layer %d" % i].append(node1)
            tree["layer %d" % i].append(node2)


    print(len(tree['layer 0']))



if __name__ == '__main__':
    # random.seed(0) # for reproducibility
    # all_0s_hash()
    leaves = [[0]*BLOCK_BYTES] * 4
    generate_merkle_tree(leaves)
