/** @file
 *****************************************************************************
 * @author     This file is part of Zupply, developed by Mohammadtaghi Badakhshan
 *      
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <cstddef>
#include <stdexcept>
#ifndef UTILS_HPP
#error "utils.tcc should not be included directly. Include utils.hpp instead."
#endif

#include "utils.hpp"
#include <libff/algebra/curves/bls12_381/bls12_381_pp.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <typeinfo>


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

    libff::G1<ppT> proof_g1A_affine_coordinates(proof.g_A);
    proof_g1A_affine_coordinates.to_affine_coordinates();

    libff::G2<ppT> proof_g2B_affine_coordinates(proof.g_B);
    proof_g2B_affine_coordinates.to_affine_coordinates();

    libff::G1<ppT> proof_g1C_affine_coordinates(proof.g_C);
    proof_g1C_affine_coordinates.to_affine_coordinates();
    
    if (std::is_same<ppT, libff::bls12_381_pp>::value) {
        // Custom handling for BLS12-381 coordinates
        proof_dec << "g_A: " << std::endl;
        proof_dec << "(" << proof_g1A_affine_coordinates.X.as_bigint().data << ", " 
                  << proof_g1A_affine_coordinates.Y.as_bigint().data << ")" << std::endl;

        proof_dec << "g_B: " << std::endl;
        proof_dec << "(" << proof_g2B_affine_coordinates.X.as_bigint().data << ", " 
                  << proof_g2B_affine_coordinates.Y.as_bigint().data << ")" << std::endl;

        proof_dec << "g_C: " << std::endl;
        proof_dec << "(" << proof_g1C_affine_coordinates.X.as_bigint().data << ", " 
                  << proof_g1C_affine_coordinates.Y.as_bigint().data << ")" << std::endl;

    } else if (std::is_same<ppT, libff::bn128_pp>::value) {
        proof_dec << "g_A: " << std::endl;
        proof_dec << "(" << proof_g1A_affine_coordinates.X.toString(10) << ", " 
                  << proof_g1A_affine_coordinates.Y.toString(10) << ")" << std::endl;

        proof_dec << "g_B: " << std::endl;
        proof_dec << "(" << proof_g2B_affine_coordinates.X.toString(10) << ", " 
                  << proof_g2B_affine_coordinates.Y.toString(10) << ")" << std::endl;

        proof_dec << "g_C: " << std::endl;        
        proof_dec << "(" << proof_g1C_affine_coordinates.X.toString(10) << ", " 
                  << proof_g1C_affine_coordinates.Y.toString(10) << ")" << std::endl;
    }


    proof_dec << "Primary (public) inputs: " << primary_input << std::endl;

    proof_dec.close();

}

template<typename FieldT, typename hash_type>
void save_proof(libiop::aurora_snark_argument<FieldT, hash_type> proof, r1cs_primary_input<FieldT> primary_input, const std::string path){
    std::ofstream proof_dec;

    proof_dec.open(path + "_argument.dec", std::ios::out | std::ios::binary);
    if (proof_dec.is_open()){
        proof.serialize(proof_dec);
        proof_dec.close();
    }
    else {
        std::cout<< "Failed to open the file";
        std::exit(EXIT_FAILURE);
    }
}


template<typename FieldT, typename HashT, typename ppT>
void save_pp(Circuit<FieldT, HashT, ppT> circuit, std::string path){
    std::ofstream pk_bin, vk_bin, vk_dec, r1cs;

    pk_bin.open(path + "pk.bin", std::ios::out | std::ios::binary);
    vk_bin.open(path + "vk.bin", std::ios::out | std::ios::binary);
    r1cs.open(path + "r1cs",   std::ios::out);

    if (pk_bin.is_open() & vk_bin.is_open() & r1cs.is_open()){
        pk_bin << circuit.get_keypair().pk;
        vk_bin << circuit.get_keypair().vk;
        r1cs << circuit.get_r1cs_constraints();
        pk_bin.close();
        vk_bin.close();
        r1cs.close();
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

    libff::G1<ppT> alpha_g1_affine_coordinates(circuit.get_keypair().pk.alpha_g1);
    alpha_g1_affine_coordinates.to_affine_coordinates();
    libff::G2<ppT> beta_g2_affine_coordinates(circuit.get_keypair().pk.beta_g2);
    beta_g2_affine_coordinates.to_affine_coordinates();
    libff::G2<ppT> gamma_g2_affine_coordinates(circuit.get_keypair().vk.gamma_g2);
    gamma_g2_affine_coordinates.to_affine_coordinates();
    libff::G2<ppT> delta_g2_affine_coordinates(circuit.get_keypair().vk.delta_g2);
    delta_g2_affine_coordinates.to_affine_coordinates();
    libff::G1<ppT> gamma_ABC_g1_affine_coordinates(circuit.get_keypair().vk.gamma_ABC_g1.first);
    gamma_ABC_g1_affine_coordinates.to_affine_coordinates();
    
    // if (std::is_same<ppT, libff::bls12_381_pp>::value) {

    
    // } else if (std::is_same<ppT, libff::bn128_pp>::value) {
    #ifdef CURVE_BN128
        vk_dec<< "alpha_g1: " << std::endl;
        vk_dec << "(" << alpha_g1_affine_coordinates.X.toString(10) << ", " << alpha_g1_affine_coordinates.Y.toString(10) << ")" << std::endl;
        vk_dec<< "beta_g2: " << std::endl;
        vk_dec << "(" << beta_g2_affine_coordinates.X.toString(10) << ", " << beta_g2_affine_coordinates.Y.toString(10) << ")" << std::endl;
        vk_dec<< "gamma_g2: " << std::endl;
        vk_dec << "(" << gamma_g2_affine_coordinates.X.toString(10) << ", " << gamma_g2_affine_coordinates.Y.toString(10) << ")" << std::endl;
        vk_dec<< "delta_g2: " << std::endl;
        vk_dec << "(" << delta_g2_affine_coordinates.X.toString(10) << ", " << delta_g2_affine_coordinates.Y.toString(10) << ")" << std::endl;
        vk_dec<< "gamma_ABC_g1: " << std::endl;
        vk_dec << " * first: " << std::endl;
        vk_dec << "(" << gamma_ABC_g1_affine_coordinates.X.toString(10) << ", " << gamma_ABC_g1_affine_coordinates.Y.toString(10) << ")" << std::endl;
    // }
    #endif

    for (size_t i = 0; i < circuit.get_primary_input().size(); ++i){
        vk_dec << " * i : " << i << std::endl;
        vk_dec << "index: " << circuit.get_keypair().vk.gamma_ABC_g1.rest.indices[i]<< std::endl;
        vk_dec << "value: " << std::endl;
        
        libff::G1<ppT> gamma_ABC_g1_rest_affine_coordinates(circuit.get_keypair().vk.gamma_ABC_g1.rest.values[i]);
        gamma_ABC_g1_rest_affine_coordinates.to_affine_coordinates();
        // if (std::is_same<ppT, libff::bls12_381_pp>::value) {

        // } else if (std::is_same<ppT, libff::bn128_pp>::value) {
        #ifdef CURVE_BN128
            vk_dec << "(" << gamma_ABC_g1_rest_affine_coordinates.X.toString(10) << ", " << gamma_ABC_g1_rest_affine_coordinates.Y.toString(10) << ")" << std::endl;
        #endif
        // }
    }
    vk_dec.close();


    
}

template<typename FieldT>
libiop::r1cs_constraint_system<FieldT> convert_libsnark_to_libiop( const r1cs_constraint_system<FieldT>& libsnart_r1cs,
                                                                    libiop::r1cs_primary_input<FieldT>& primary_input,
	                                                                libiop::r1cs_auxiliary_input<FieldT>& auxiliary_input){
    
    libiop::r1cs_constraint_system<FieldT> libiop_r1cs = convert_libsnark_to_libiop(libsnart_r1cs);
    
    size_t moving_inputs = libiop_r1cs.num_inputs() - primary_input.size();
    std::cout << "moving_inputs: " << moving_inputs << std::endl;

    for (size_t i = 0; i < moving_inputs; ++i){
        if (auxiliary_input[i] != 0)
        throw std::invalid_argument("the moving inputs from the auxilary input has to be 0");
    }

    primary_input.insert(primary_input.end(), 
                         std::make_move_iterator(auxiliary_input.begin()), 
                         std::make_move_iterator(auxiliary_input.begin() + moving_inputs));
    
    auxiliary_input.erase(auxiliary_input.begin(), auxiliary_input.begin() + moving_inputs);

    return libiop_r1cs;
}

template<typename FieldT>
libiop::r1cs_constraint_system<FieldT> convert_libsnark_to_libiop( const r1cs_constraint_system<FieldT>& libsnart_r1cs){
    libiop::r1cs_constraint_system<FieldT> libiop_r1cs;
    libiop_r1cs.primary_input_size_ = libsnart_r1cs.primary_input_size;
    libiop_r1cs.auxiliary_input_size_ = libsnart_r1cs.auxiliary_input_size;

    for (r1cs_constraint<FieldT> libsnark_constraint: libsnart_r1cs.constraints){
        std::vector<libiop::linear_combination<FieldT>> m_libiop (3); // a, b, and c matrix

        size_t cnt = 0;
        for (linear_combination<FieldT> m_libsnark: {libsnark_constraint.a, libsnark_constraint.b, libsnark_constraint.c}){
            for (linear_term<FieldT> libsnark_linear_term: m_libsnark){
                m_libiop[cnt].add_term(libiop::variable<FieldT>(libsnark_linear_term.index),
                                       libsnark_linear_term.coeff);
            }
            cnt ++;
        }
        libiop_r1cs.add_constraint(libiop::r1cs_constraint<FieldT> (m_libiop[0], m_libiop[1], m_libiop[2]));
    }


    size_t next_power_of_two = 1ull << libff::log2(libiop_r1cs.num_constraints());
    size_t pad_amount = next_power_of_two - (libiop_r1cs.num_constraints());
    for (std::size_t i = 0; i < pad_amount; ++i){
        libiop_r1cs.add_constraint(libiop::r1cs_constraint<FieldT> ());
    }

    libiop_r1cs.primary_input_size_ += (1ull << libff::log2(libiop_r1cs.num_inputs() + 1)) - (libiop_r1cs.num_inputs() + 1) ;
    libiop_r1cs.auxiliary_input_size_ += (1ull << libff::log2(libiop_r1cs.num_variables() + 1)) - (libiop_r1cs.num_variables() + 1) ;
    

    return libiop_r1cs;
}

template<typename FieldT, typename hash_type>
libiop::aurora_snark_parameters<FieldT, hash_type> generate_aurora_parameters( libiop::r1cs_constraint_system<FieldT> libiop_r1cs){

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

    return params;
}



template <typename FieldT, typename HashT, typename ppT>
std::unique_ptr<Circuit<FieldT, HashT, ppT>> selectCircuit(int circuit_selector, int tree_depth){
    std::unique_ptr<Circuit<FieldT, HashT, ppT>> circuit;
    
    switch (circuit_selector) {
        case Select_AuthCircuit:
        default:
            circuit = std::make_unique<AuthCircuit<FieldT, HashT, ppT>>("AuthCircuit", tree_depth);
            break;
        
        case Select_TransCircuit:
            circuit = std::make_unique<TransCircuit<FieldT, HashT, ppT>>("TransCircuit", tree_depth);
            break;
        
        case Select_MergeCircuit:
            circuit = std::make_unique<MergeCircuit<FieldT, HashT, ppT>>("MergeCircuit", tree_depth);
            break;
        
        case Select_DivCircuit:
            circuit = std::make_unique<DivCircuit<FieldT, HashT, ppT>>("DivCircuit", tree_depth);
            break;
    }
    
    return circuit;
}
