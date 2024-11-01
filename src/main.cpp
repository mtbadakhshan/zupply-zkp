/** @file
 *****************************************************************************
 * @author     This file is part of Zupply, developed by Mohammadtaghi Badakhshan
 *      
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifdef CURVE_BN128
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#endif

#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/bn128/bn128_init.hpp>
#include <libff/algebra/curves/bn128/bn128_g1.hpp>
#include <libff/algebra/curves/bn128/bn_utils.hpp>


// #include <libff/algebra/curves/public_params.hpp>
// #ifdef CURVE_ALT_BN128
// #include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
// #endif

// #ifndef NDEBUG
// #define NDEBUG

#include <iostream>
#include <fstream>
#include <string>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "depends/ate-pairing/include/bn.h"

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/crh_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/digest_selector_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>

// #include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
// #include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"


#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"

#include "libiop/algebra/utils.hpp"
#include "libiop/relations/r1cs.hpp"
#include <libiop/snark/aurora_snark.hpp>
#include <libiop/protocols/ldt/ldt_reducer.hpp>

#include <libff/algebra/fields/binary/gf128.hpp>

#include "np_circuits/circuit.hpp"
#include "utils.hpp"


using namespace libsnark;



template<typename FieldT, typename HashT, typename ppT>
void proof_auth()
{
    std::srand ( std::time(NULL) ); 
    std::string circuit_type = "DivCircuit";
    const size_t tree_depth = 20;

    DivCircuit<FieldT, HashT, ppT> circuit("circuit", tree_depth);
    
    // if (circuit_type.compare("AuthCircuit") == 0)
    //     AuthCircuit<FieldT, HashT, ppT> circuit("circuit", tree_depth);
    // else if (circuit_type.compare("TransCircuit") == 0)
    //     TransCircuit<FieldT, HashT, ppT> circuit("circuit", tree_depth);
    // else if (circuit_type.compare("MergeCircuit") == 0)
    //     MergeCircuit<FieldT, HashT, ppT> circuit("circuit", tree_depth);   
    // // else if (circuit_type.compare("DivCircuit") == 0)
    //     // DivCircuit<FieldT, HashT, ppT> circuit("circuit", tree_depth);   
    // else{
    //     AuthCircuit<FieldT, HashT, ppT> circuit("circuit", tree_depth);
    // }


    std::string path = "../pp/" + circuit_type + "/";
    save_pp<FieldT, HashT, ppT>(circuit, path);
    

    printf("Generating proof:!\n");
    const r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(circuit.get_keypair().pk,
                                                                        circuit.get_primary_input(),
                                                                        circuit.get_auxiliary_input());

    save_proof<FieldT, HashT, ppT>(proof,  circuit.get_primary_input(), path);
    printf("Verifing:!\n");
    bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(circuit.get_keypair().vk, 
                                                                        circuit.get_primary_input(), 
                                                                        proof);

    //// RUN IN LIBIOP ////
    libiop::r1cs_constraint_system<FieldT> libiop_r1cs = convert_libsnark_to_libiop<FieldT>(circuit.get_r1cs_constraints());
    std::cout << "libiop_r1cs.is_satisfied(): " <<  libiop_r1cs.is_satisfied(circuit.get_primary_input(), circuit.get_auxiliary_input()) << std::endl;
`   


    // std::cout << "Number of inputs: " << pb.num_inputs() << std::endl;
    std::cout << "FieldT::floor_size_in_bits(): " << FieldT::floor_size_in_bits() << std::endl; 
    std::cout << "Verification Key Size: " << std::endl;
    circuit.get_keypair().vk.print_size();
    std::cout << "circuit.get_primary_input().size(): " << circuit.get_primary_input().size() << std::endl;
    std::cout << "Verification status: " << verified << std::endl;




}


template<typename FieldT, typename HashT, typename ppT>
int libiop_example(){
    std::cout << "##### Libiop #####" << std::endl;
    libiop::r1cs_constraint_system<FieldT> constraint_system_;
    protoboard<FieldT> pb;


    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");

    sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
    f.generate_r1cs_constraints();
    printf("Number of constraints for sha256_two_to_one_hash_gadget: %zu\n", pb.num_constraints());

    const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
    const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
    const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

    left.generate_r1cs_witness(left_bv);
    right.generate_r1cs_witness(right_bv);

    f.generate_r1cs_witness();
    output.generate_r1cs_witness(hash_bv);

    assert(pb.is_satisfied());
    std::cout<<"pb.is_satisfied(): " << pb.is_satisfied() << std::endl;

    r1cs_constraint_system<FieldT> libsnart_r1cs = pb.get_constraint_system();
    r1cs_primary_input<FieldT> libsnark_primary_input = pb.primary_input();
    r1cs_auxiliary_input<FieldT> libsnark_auxilary_input = pb.auxiliary_input();

    std::vector<r1cs_constraint<FieldT> > libsnark_constraints = libsnart_r1cs.constraints;

    std::vector<linear_term<FieldT> > a_terms = libsnark_constraints[0].a.terms;


    libiop::r1cs_constraint_system<FieldT> libiop_r1cs = convert_libsnark_to_libiop<FieldT>(libsnart_r1cs);

    std::cout << "libiop_r1cs.is_valid(): " <<  libiop_r1cs.is_valid() << std::endl;
    // std::cout << "pb.primary_input(): " <<  pb.primary_input() << std::endl;
    // std::cout << "pb.auxiliary_input(): " <<  pb.auxiliary_input() << std::endl;

    std::cout << "libiop_r1cs.is_satisfied(): " <<  libiop_r1cs.is_satisfied(pb.primary_input(), pb.auxiliary_input()) << std::endl;

    
    typedef libiop::binary_hash_digest hash_type;
    const size_t num_constraints = libiop_r1cs.num_constraints();
    const size_t num_inputs = libiop_r1cs.num_inputs();
    const size_t num_variables = libiop_r1cs.num_variables();
    const size_t security_parameter = 128;
    const size_t RS_extra_dimensions = 2;
    const size_t FRI_localization_parameter = 3;
    const libiop::LDT_reducer_soundness_type ldt_reducer_soundness_type = libiop::LDT_reducer_soundness_type::optimistic_heuristic;
    const libiop::FRI_soundness_type fri_soundness_type = libiop::FRI_soundness_type::heuristic;
    const libiop::field_subset_type domain_type = libiop::multiplicative_coset_type;

    /* Actual SNARK test */
    const bool make_zk = true;
    libiop::aurora_snark_parameters<FieldT, hash_type> params(
        security_parameter,
        ldt_reducer_soundness_type,
        fri_soundness_type,
        libiop::blake2b_type,
        FRI_localization_parameter,
        RS_extra_dimensions,
        make_zk,
        domain_type,
        num_constraints,
        num_variables);

    std::cout << "here! 1" << std::endl;

    const libiop::aurora_snark_argument<FieldT, hash_type> argument = libiop::aurora_snark_prover<FieldT>(
        libiop_r1cs,
        pb.primary_input(),
        pb.auxiliary_input(),
        params);

    // save_proof<FieldT, hash_type>(argument, pb.primary_input(), "");

    printf("iop size in bytes %lu\n", argument.IOP_size_in_bytes());
    printf("bcs size in bytes %lu\n", argument.BCS_size_in_bytes());
    printf("argument size in bytes %lu\n", argument.size_in_bytes());
    const bool bit = libiop::aurora_snark_verifier<FieldT>(
        libiop_r1cs,
        pb.primary_input(),
        argument,
        params);

    std::cout << "bit : " << bit << std::endl;
    return 0;
}

int main(void)

{
    libff::start_profiling();
    libff::bn128_pp::init_public_params();
    typedef libff::Fr<libff::bn128_pp> FieldT;
    proof_auth<FieldT, libsnark::sha256_two_to_one_hash_gadget<FieldT>, libff::bn128_pp>();
    // libiop_example<FieldT, libsnark::sha256_two_to_one_hash_gadget<FieldT>, libff::bn128_pp>();


}
