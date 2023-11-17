/** @file
 *****************************************************************************
 * @author     This file is part of Zupply, developed by Mohammadtaghi Badakhshan
 *      
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef UTILS_HPP
#error "utils.tcc should not be included directly. Include utils.hpp instead."
#endif

#include "utils.hpp"

// using namespace libsnark;

template<typename FieldT, typename HashT, typename ppT>
void save_proof(r1cs_gg_ppzksnark_proof<ppT> proof, r1cs_primary_input<FieldT> primary_input, const std::string path){
    std::ofstream proof_bin, proof_dec;

    proof_bin.open(path + "proof.bin", std::ios::out | std::ios::binary);
    if (proof_bin.is_open()){
        proof_bin << proof;
        proof_bin.close();
    }
    else {
        std::cout<< "Failed to open the file";
        std::exit(EXIT_FAILURE);
    }

    proof_dec.open(path + "proof.dec", std::ios::out);
    if (!proof_dec.is_open()){
        std::cout<< "Failed to open the file";
        std::exit(EXIT_FAILURE);
    }

    proof_dec<< "Proof: " << std::endl;

    proof_dec << "g_A: " << std::endl;
    libff::G1<ppT> proof_g1A_affine_coordinates(proof.g_A);
    proof_g1A_affine_coordinates.to_affine_coordinates();
    proof_dec << "(" << proof_g1A_affine_coordinates.coord[0].toString(10) << ", " << proof_g1A_affine_coordinates.coord[1].toString(10) << ")" << std::endl;
    // proof.g_A.print();

    proof_dec << "g_B: " << std::endl;
    libff::G2<ppT> proof_g2B_affine_coordinates(proof.g_B);
    proof_g2B_affine_coordinates.to_affine_coordinates();
    proof_dec << "(" << proof_g2B_affine_coordinates.coord[0].toString(10) << ", " << proof_g2B_affine_coordinates.coord[1].toString(10) << ")" << std::endl;
    proof.g_B.print();


    proof_dec << "g_C: " << std::endl;
     libff::G1<ppT> proof_g1C_affine_coordinates(proof.g_C);
    proof_g1C_affine_coordinates.to_affine_coordinates();
    proof_dec << "(" << proof_g1C_affine_coordinates.coord[0].toString(10) << ", " << proof_g1C_affine_coordinates.coord[1].toString(10) << ")" << std::endl;
    // proof.g_C.print();

    proof_dec << "Primary (public) inputs: " << primary_input << std::endl;

    proof_dec.close();

}

template<typename FieldT, typename HashT, typename ppT>
void save_pp(Circuit<FieldT, HashT, ppT> circuit, std::string path){
    std::ofstream pk_bin, vk_bin, vk_dec;

    pk_bin.open(path + "pk.bin", std::ios::out | std::ios::binary);
    vk_bin.open(path + "vk.bin", std::ios::out | std::ios::binary);
    // vk_hex.open(path + "pk.bin", std::ios::out | std::ios::binary);

    if (pk_bin.is_open() & vk_bin.is_open()){
        pk_bin << circuit.get_keypair().pk;
        vk_bin << circuit.get_keypair().vk;
        pk_bin.close();
        vk_bin.close();
    }
    else {
        std::cout<< "Failed to open the file";
        std::exit(EXIT_FAILURE);
    }


    vk_dec.open(path + "vk.dec", std::ios::out);

    if (!vk_dec.is_open()){
        std::cout<< "Failed to open the file";
        std::exit(EXIT_FAILURE);
    }

    vk_dec<< "Verification Key: " << std::endl;

    vk_dec<< "alpha_g1: " << std::endl;
    libff::G1<ppT> alpha_g1_affine_coordinates(circuit.get_keypair().pk.alpha_g1);
    alpha_g1_affine_coordinates.to_affine_coordinates();
    vk_dec << "(" << alpha_g1_affine_coordinates.coord[0].toString(10) << ", " << alpha_g1_affine_coordinates.coord[1].toString(10) << ")" << std::endl;


    vk_dec<< "beta_g2: " << std::endl;
    libff::G2<ppT> beta_g2_affine_coordinates(circuit.get_keypair().pk.beta_g2);
    beta_g2_affine_coordinates.to_affine_coordinates();
    vk_dec << "(" << beta_g2_affine_coordinates.coord[0].toString(10) << ", " << beta_g2_affine_coordinates.coord[1].toString(10) << ")" << std::endl;

    vk_dec<< "gamma_g2: " << std::endl;
    libff::G2<ppT> gamma_g2_affine_coordinates(circuit.get_keypair().vk.gamma_g2);
    gamma_g2_affine_coordinates.to_affine_coordinates();
    vk_dec << "(" << gamma_g2_affine_coordinates.coord[0].toString(10) << ", " << gamma_g2_affine_coordinates.coord[1].toString(10) << ")" << std::endl;

    vk_dec<< "delta_g2: " << std::endl;
    libff::G2<ppT> delta_g2_affine_coordinates(circuit.get_keypair().vk.delta_g2);
    delta_g2_affine_coordinates.to_affine_coordinates();
    vk_dec << "(" << delta_g2_affine_coordinates.coord[0].toString(10) << ", " << delta_g2_affine_coordinates.coord[1].toString(10) << ")" << std::endl;

    vk_dec<< "gamma_ABC_g1: " << std::endl;
    vk_dec << " * first: " << std::endl;
    libff::G1<ppT> gamma_ABC_g1_affine_coordinates(circuit.get_keypair().vk.gamma_ABC_g1.first);
    gamma_ABC_g1_affine_coordinates.to_affine_coordinates();
    vk_dec << "(" << gamma_ABC_g1_affine_coordinates.coord[0].toString(10) << ", " << gamma_ABC_g1_affine_coordinates.coord[1].toString(10) << ")" << std::endl;
    

    for (size_t i = 0; i < circuit.get_primary_input().size(); ++i){
        vk_dec << " * i : " << i << std::endl;
        vk_dec << "index: " << circuit.get_keypair().vk.gamma_ABC_g1.rest.indices[i]<< std::endl;
        vk_dec << "value: " << std::endl;
        
        libff::G1<ppT> gamma_ABC_g1_rest_affine_coordinates(circuit.get_keypair().vk.gamma_ABC_g1.rest.values[i]);
        gamma_ABC_g1_rest_affine_coordinates.to_affine_coordinates();
        vk_dec << "(" << gamma_ABC_g1_rest_affine_coordinates.coord[0].toString(10) << ", " << gamma_ABC_g1_rest_affine_coordinates.coord[1].toString(10) << ")" << std::endl;
    }
    vk_dec.close();
}