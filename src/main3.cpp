/**
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifdef CURVE_BN128
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#endif

// #ifndef NDEBUG
// #define NDEBUG


#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

using namespace libsnark;

template<typename ppT>
void test_all_merkle_tree_gadgets()
{
    typedef libff::Fr<ppT> FieldT;
    test_merkle_tree_check_read_gadget<FieldT, CRH_with_bit_out_gadget<FieldT> >();
    test_merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT> >();

    test_merkle_tree_check_update_gadget<FieldT, CRH_with_bit_out_gadget<FieldT> >();
    test_merkle_tree_check_update_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT> >();
}

template<typename FieldT, typename HashT>
void test_merkle_tree()
{

    /* prepare test */
    const size_t digest_len = HashT::get_digest_len();
    const size_t tree_depth = 16;
    std::vector<merkle_authentication_node> path(tree_depth);

    libff::bit_vector prev_hash(digest_len);
    std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
    libff::bit_vector leaf = prev_hash;

    libff::bit_vector address_bits;

    size_t address = 0;
    for (long level = tree_depth-1; level >= 0; --level)
    {
        const bool computed_is_right = (std::rand() % 2);
        address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
        address_bits.push_back(computed_is_right);
        libff::bit_vector other(digest_len);
        std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

        libff::bit_vector block = prev_hash;
        block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
        libff::bit_vector h = HashT::get_hash(block);

        path[level] = other;

        prev_hash = h;
    }
    libff::bit_vector root = prev_hash;


    /* execute test */
    protoboard<FieldT> pb;
    pb_variable_array<FieldT> address_bits_va;
    address_bits_va.allocate(pb, tree_depth, "address_bits");
    digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
    digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");
    merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
    printf("tree_depth = %ld\n", tree_depth);
    merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

    // path_var.generate_r1cs_constraints();
    // ml.generate_r1cs_constraints();

    // address_bits_va.fill_with_bits(pb, address_bits);
    // assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
    // leaf_digest.generate_r1cs_witness(leaf);
    // path_var.generate_r1cs_witness(address, path);
    // ml.generate_r1cs_witness();

    // /* make sure that read checker didn't accidentally overwrite anything */
    // address_bits_va.fill_with_bits(pb, address_bits);
    // leaf_digest.generate_r1cs_witness(leaf);
    // root_digest.generate_r1cs_witness(root);
    // assert(pb.is_satisfied());

    // const size_t num_constraints = pb.num_constraints();
    // const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
    // assert(num_constraints == expected_constraints);

}


int main(void)

{
    typedef libff::Fr<libff::bn128_pp> FieldT;
    test_merkle_tree<FieldT, sha256_two_to_one_hash_gadget<FieldT> >();
}
