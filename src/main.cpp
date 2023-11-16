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
#include <fstream>
#include <string>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

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


using namespace libsnark;


template<typename FieldT, typename HashT, typename ppT>
void save_pp(Circuit<FieldT, HashT, ppT> circuit, std::string path){
    std::ofstream pk_bin, vk_bin, vk_hex;

    pk_bin.open(path + "pk.bin", std::ios::out | std::ios::binary);
    vk_bin.open(path + "vk.bin", std::ios::out | std::ios::binary);
    // vk_hex.open(path + "pk.bin", std::ios::out | std::ios::binary);

    if (pk_bin.is_open() & vk_bin.is_open()){
        pk_bin << circuit.get_keypair().pk;
        vk_bin << circuit.get_keypair().vk;
        pk_bin.close();
    }
    else {
        std::cout<< "Failed to open the file";
        std::exit(EXIT_FAILURE);
    }
    
}

template<typename FieldT, typename HashT, typename ppT>
void proof_auth()
{

    std::srand ( std::time(NULL) );   
    
    const size_t tree_depth = 20;

    AuthCircuit<FieldT, HashT, ppT> circuit("circuit", tree_depth);
    std::string path = "../keys/AuthCircuit/";
    
    save_pp<FieldT, HashT, ppT>(circuit, path);


    std::cout << "Primary (public) input: " << circuit.get_primary_input() << std::endl;

    

    printf("Generating proof:!\n");
    const r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(circuit.get_keypair().pk,
                                                                        circuit.get_primary_input(),
                                                                        circuit.get_auxiliary_input());


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
    std::cout << "Verification Key: " << std::endl;

    

    // std::cout << "alpha_g1_beta_g2: " << std::endl;
    // circuit.get_keypair().vk.alpha_g1_beta_g2.print();
    std::cout << "alpha_g1: " << std::endl;
    circuit.get_keypair().pk.alpha_g1.print();

    std::cout << "beta_g2: " << std::endl;
    circuit.get_keypair().pk.beta_g2.print();

    std::cout << "gamma_g2: " << std::endl;
    circuit.get_keypair().vk.gamma_g2.print();

    std::cout << "delta_g2: " << std::endl;
    circuit.get_keypair().vk.delta_g2.print();

    std::cout << "gamma_ABC_g1: " << std::endl;
    std::cout << " * first: " << std::endl;
    circuit.get_keypair().vk.gamma_ABC_g1.first.print();
    

    for (size_t i = 0; i < 2; ++i){
        std::cout << " * i : " << i << "" << std::endl;
        std::cout<< "index: " << circuit.get_keypair().vk.gamma_ABC_g1.rest.indices[i];
        std::cout<< "value: " << std::endl;
        circuit.get_keypair().vk.gamma_ABC_g1.rest.values[i].print();
    }

        // std::cout << circuit.get_keypair().vk.gamma_ABC_g1 << std::endl;

    std::cout<< "Proof: " << std::endl;

    std::cout << "g_A: " << std::endl;
    proof.g_A.print();
    std::cout << "g_B: " << std::endl;
    proof.g_B.print();
    std::cout << "g_C: " << std::endl;
    proof.g_C.print();


    std::cout << "Primary (public) input: " << circuit.get_primary_input() << std::endl;
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
