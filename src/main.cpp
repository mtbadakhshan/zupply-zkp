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

#include "circuit.hpp"
#include "utils.hpp"


using namespace libsnark;



template<typename FieldT, typename HashT, typename ppT>
void proof_auth()
{
    std::srand ( std::time(NULL) ); 
    std::string circuit_type = "MergeCircuit";
    const size_t tree_depth = 20;

    MergeCircuit<FieldT, HashT, ppT> circuit("circuit", tree_depth);
    
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


    std::cout << "Primary (public) input: " << circuit.get_primary_input() << std::endl;

    

    printf("Generating proof:!\n");
    const r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(circuit.get_keypair().pk,
                                                                        circuit.get_primary_input(),
                                                                        circuit.get_auxiliary_input());


    save_proof<FieldT, HashT, ppT>(proof,  circuit.get_primary_input(), path);
    printf("Verifing:!\n");
    bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(circuit.get_keypair().vk, 
                                                                        circuit.get_primary_input(), 
                                                                        proof);

    std::cout << "FOR SUCCESSFUL VERIFICATION" << std::endl;
    // std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << std::endl;
    // std::cout << "Number of inputs: " << pb.num_inputs() << std::endl;
    std::cout << "FieldT::capacity(): " << FieldT::capacity() << std::endl; 
    std::cout << "Verification Key Size: " << std::endl;
    circuit.get_keypair().vk.print_size();
    

        // std::cout << circuit.get_keypair().vk.gamma_ABC_g1 << std::endl;

    std::cout<< "Proof: " << std::endl;

    std::cout << "g_A: " << std::endl;
    proof.g_A.print();
    std::cout << "g_B: " << std::endl;
    proof.g_B.print();
    std::cout << "g_C: " << std::endl;
    proof.g_C.print();

    std::cout << "circuit.get_primary_input().size(): " << circuit.get_primary_input().size() << std::endl;
    // std::cout << "Primary (public) input: " << circuit.get_primary_input() << std::endl;
    // std::cout << "num_inputs: " << pb.num_inputs() << std::endl;
    // std::cout << "root: ";
    // for(int i = 0; i < digest_len; i++){
    //     std::cout  << root[i] ;
    // }
    
    // std::cout << "Auxiliary (private) input: " << pb.auxiliary_input() << std::endl;
    std::cout << "Verification status: " << verified << std::endl;

    // std::cout << "address: " << address << std::endl;

    

}



int main(void)

{
    libff::start_profiling();
    libff::bn128_pp::init_public_params();
    typedef libff::Fr<libff::bn128_pp> FieldT;
    proof_auth<FieldT, libsnark::sha256_two_to_one_hash_gadget<FieldT>, libff::bn128_pp>();

}
