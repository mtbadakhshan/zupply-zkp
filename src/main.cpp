/**
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

// #ifdef CURVE_BN128
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
// #endif

#ifdef CURVE_ALT_BN128
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif

// #ifndef NDEBUG
// #define NDEBUG

#include <iostream>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/crh_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/digest_selector_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"


using namespace libsnark;

// template<typename ppT>
// void test_all_merkle_tree_gadgets()
// {
//     typedef libff::Fr<ppT> FieldT;
//     test_merkle_tree_check_read_gadget<FieldT, CRH_with_bit_out_gadget<FieldT> >();
//     test_merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT> >();

//     test_merkle_tree_check_update_gadget<FieldT, CRH_with_bit_out_gadget<FieldT> >();
//     test_merkle_tree_check_update_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT> >();
// }

template<typename FieldT, typename HashT, typename ppT>
void proof_auth()
{

    const size_t digest_len = HashT::get_digest_len();

     
    /* Make a Protoboard */
    protoboard<FieldT> pb;

    
    /* Inputs */
    digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");
    // block_variable<FieldT> input(pb, SHA256_block_size, "input");

    /* Building the MHT */
    const size_t tree_depth = 2;
    pb_variable_array<FieldT> address_bits_va;
    address_bits_va.allocate(pb, tree_depth, "address_bits");
    digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
    
    merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
    merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

    /* Build CRH to get commitment cm */
    // digest_variable<FieldT> cm(pb, SHA256_digest_size, "cm");
    // sha256_two_to_one_hash_gadget<FieldT> crh(pb, SHA256_block_size, input, leaf_digest, "crh");

    pb.set_input_sizes(digest_len);
    /* prepare test */

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



    
   
    path_var.generate_r1cs_constraints();
    ml.generate_r1cs_constraints();
    // crh.generate_r1cs_constraints();

    root_digest.generate_r1cs_witness(root);
    address_bits_va.fill_with_bits(pb, address_bits);
    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
    leaf_digest.generate_r1cs_witness(leaf);
    path_var.generate_r1cs_witness(address, path);
    ml.generate_r1cs_witness();

    
    

    /* make sure that read checker didn't accidentally overwrite anything */
    address_bits_va.fill_with_bits(pb, address_bits);
    leaf_digest.generate_r1cs_witness(leaf);
    root_digest.generate_r1cs_witness(root);
    assert(pb.is_satisfied());

    const size_t num_constraints = pb.num_constraints();
    const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
    assert(num_constraints == expected_constraints);



    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(constraint_system);


    libff::print_header("Preprocess verification key");
    r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(keypair.vk);


    printf("Generating proof:!\n");

    const r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input());


    printf("Verifing:!\n");
    bool verified = r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, pb.primary_input(), proof);

    std::cout << "FOR SUCCESSFUL VERIFICATION" << std::endl;
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << std::endl;
    std::cout << "Number of inputs: " << pb.num_inputs() << std::endl;
    std::cout << "Primary (public) input: " << pb.primary_input() << std::endl;
    // std::cout << "num_inputs: " << pb.num_inputs() << std::endl;
    std::cout << "root: ";
    for(int i = 0; i < digest_len; i++){
        std::cout  << root[i] ;
    }
    
    std::cout << "Auxiliary (private) input: " << pb.auxiliary_input() << std::endl;
    std::cout << "Verification status: " << verified << std::endl;

    std::cout << "address: " << address << std::endl;

    printf("Here2!\n");

}



int main(void)

{
    libff::start_profiling();
    libff::bn128_pp::init_public_params();
    typedef libff::Fr<libff::bn128_pp> FieldT;
    proof_auth<FieldT, libsnark::sha256_two_to_one_hash_gadget<FieldT>, libff::bn128_pp>();

}
