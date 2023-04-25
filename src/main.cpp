/**
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifdef CURVE_BN128
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#endif

// #ifdef CURVE_ALT_BN128
// #include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
// #endif

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

#include "circuit.hpp"


using namespace libsnark;



/* Trusted Setup */
template<typename FieldT, typename HashT>
protoboard<FieldT> setup_auth()
{
    const size_t digest_len = HashT::get_digest_len();
     
    /* Make a Protoboard */
    protoboard<FieldT> pb;
    
    /* Public Inputs */
    digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");

    /* Private Inputs */
    block_variable<FieldT> input(pb, SHA256_block_size, "input"); //It's "q", "PK_sig", rho

    /* Building the MHT */
    const size_t tree_depth = 2;
    pb_variable_array<FieldT> address_bits_va;
    address_bits_va.allocate(pb, tree_depth, "address_bits");
    digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
    merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
    merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

    /* Building CRH to get commitment cm */
    digest_variable<FieldT> cm(pb, SHA256_digest_size, "cm");
    sha256_two_to_one_hash_gadget<FieldT> crh(pb, SHA256_block_size, input, leaf_digest, "crh");

    /* Setting the public input*/ 
    //the first 256 bits assigned to the protoboard which are root_digest's bits, are determined as public inputs */
    pb.set_input_sizes(digest_len);

    crh.generate_r1cs_constraints();
    path_var.generate_r1cs_constraints();
    ml.generate_r1cs_constraints();


    return pb;
}



template<typename FieldT, typename HashT, typename ppT>
void proof_auth()
{


    // std::srand(10);
    // const size_t digest_len = HashT::get_digest_len();
    const size_t tree_depth = 2;

    MergeCircuit<FieldT, HashT, ppT> circuit("circuit", tree_depth);
    return;

    /* Make a Protoboard */
    // protoboard<FieldT> pb;

    
    // /* Public Inputs */
    // digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");


    // /* Private Inputs */
    // block_variable<FieldT> input(pb, SHA256_block_size, "input"); //It's "q", "PK_sig", rho

    // /* Building the MHT */
    
    // pb_variable_array<FieldT> address_bits_va;
    // address_bits_va.allocate(pb, tree_depth, "address_bits");
    // digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
    
    // merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
    // merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

    // /* Build CRH to get commitment cm */
    // digest_variable<FieldT> cm(pb, SHA256_digest_size, "cm");
    // sha256_two_to_one_hash_gadget<FieldT> crh(pb, SHA256_block_size, input, leaf_digest, "crh");

    // pb.set_input_sizes(digest_len);
    

    // crh.generate_r1cs_constraints();
    // path_var.generate_r1cs_constraints();
    // ml.generate_r1cs_constraints();

    // /* Functional Make a Protoboard */
    // // protoboard<FieldT> pb = setup_auth<FieldT, libsnark::sha256_two_to_one_hash_gadget<FieldT>, libff::bn128_pp>();

    // const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    // const r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(constraint_system);


    //  const size_t num_constraints = pb.num_constraints();
    // const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth)
    //                                         + sha256_two_to_one_hash_gadget<FieldT>::expected_constraints(SHA256_block_size);
    // assert(num_constraints == expected_constraints);

    // if (num_constraints != expected_constraints){
    //     std::cerr <<  "num_constraints:" << num_constraints << ",  expected_constraints:" << expected_constraints << std::endl;
    //     return;
    // }


    // // /* prepare test */

    // std::vector<merkle_authentication_node> path(tree_depth);

    
    // /* Generating random input */
    // // In actual implementation it should be generated secretly and passed by the user.    
    // libff::bit_vector input_bits(SHA256_block_size);
    // std::generate(input_bits.begin(), input_bits.end(), [&]() { return std::rand() % 2; });
    // libff::bit_vector leaf = HashT::get_hash(input_bits);


    // libff::bit_vector prev_hash = leaf;

    // // std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
    // // libff::bit_vector leaf = prev_hash;

    // libff::bit_vector address_bits;

    // size_t address = 0;
    // for (long level = tree_depth-1; level >= 0; --level)
    // {
    //     const bool computed_is_right = (std::rand() % 2);
    //     address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
    //     address_bits.push_back(computed_is_right);
    //     libff::bit_vector other(digest_len);
    //     std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

    //     libff::bit_vector block = prev_hash;
    //     block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
    //     libff::bit_vector h = HashT::get_hash(block);

    //     path[level] = other;

    //     prev_hash = h;
    // }
    // libff::bit_vector root = prev_hash;





    // root_digest.generate_r1cs_witness(root);
    // address_bits_va.fill_with_bits(pb, address_bits);
    // assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
    // leaf_digest.generate_r1cs_witness(leaf);
    // input.generate_r1cs_witness(input_bits);

    // path_var.generate_r1cs_witness(address, path);
    // ml.generate_r1cs_witness();
    // crh.generate_r1cs_witness();

    
    

    // /* make sure that read checker didn't accidentally overwrite anything */
    // address_bits_va.fill_with_bits(pb, address_bits);
    // leaf_digest.generate_r1cs_witness(leaf);
    // root_digest.generate_r1cs_witness(root);
    // input.generate_r1cs_witness(input_bits);
    // assert(pb.is_satisfied());

   


    

    libff::print_header("Preprocess verification key");
    r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(
                                                                        circuit.get_keypair().vk);


    printf("Generating proof:!\n");
    const r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(circuit.get_keypair().pk,
                                                                        circuit.get_primary_input(),
                                                                        circuit.get_auxiliary_input());


    printf("Verifing:!\n");
    bool verified = r1cs_ppzksnark_verifier_strong_IC<ppT>(circuit.get_keypair().vk, 
                                                                        circuit.get_primary_input(), 
                                                                        proof);

    std::cout << "FOR SUCCESSFUL VERIFICATION" << std::endl;
    // std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << std::endl;
    // std::cout << "Number of inputs: " << pb.num_inputs() << std::endl;
    // std::cout << "Primary (public) input: " << pb.primary_input() << std::endl;
    // std::cout << "num_inputs: " << pb.num_inputs() << std::endl;
    // std::cout << "root: ";
    // for(int i = 0; i < digest_len; i++){
    //     std::cout  << root[i] ;
    // }
    
    // std::cout << "Auxiliary (private) input: " << pb.auxiliary_input() << std::endl;
    std::cout << "Verification status: " << verified << std::endl;

    // std::cout << "address: " << address << std::endl;

    printf("Here2!\n");

}



int main(void)

{
    libff::start_profiling();
    libff::bn128_pp::init_public_params();
    typedef libff::Fr<libff::bn128_pp> FieldT;
    proof_auth<FieldT, libsnark::sha256_two_to_one_hash_gadget<FieldT>, libff::bn128_pp>();

}
