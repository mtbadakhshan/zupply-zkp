/** @file
 *****************************************************************************
 * @author     This file is part of Zupply, developed by Mohammadtaghi Badakhshan
 *      
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef CIRCUIT_HPP
#define CIRCUIT_HPP

#include <iostream>
#include <vector>
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

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"

using namespace libsnark;


template<typename FieldT>
class is_equal_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> a;
    pb_variable_array<FieldT> b;

    is_equal_gadget(protoboard<FieldT>& pb,
            const pb_variable_array<FieldT>& a_,
            const pb_variable_array<FieldT>& b_,
            const std::string& annotation_prefix = "")
        : gadget<FieldT>(pb, annotation_prefix), a(a_), b(b_)
    {
        assert(a.size() == b.size());
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < a.size(); ++i) {
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                linear_combination<FieldT>({a[i]}),
                linear_combination<FieldT>({FieldT::one()}),
                linear_combination<FieldT>({b[i]}))
            );
        }
    }
};



template<typename FieldT, typename HashT, typename ppT>
class Circuit
	{
	public:
		const std::string name;
		Circuit(const std::string& name) : name(name) {}
		r1cs_gg_ppzksnark_keypair<ppT> get_keypair() { return keypair; }
		r1cs_primary_input<FieldT> get_primary_input() { return primary_input; }
		r1cs_auxiliary_input<FieldT> get_auxiliary_input() { return auxiliary_input; }

	protected:
		r1cs_gg_ppzksnark_keypair<ppT> keypair;
		r1cs_primary_input<FieldT> primary_input;
		r1cs_auxiliary_input<FieldT> auxiliary_input;
	};


template<typename FieldT, typename HashT, typename ppT>
class AuthCircuit : public Circuit<FieldT, HashT, ppT>
	{
	public:
		AuthCircuit(const std::string& name, const size_t tree_depth);
		// void setup (libff::bit_vector input_bits,
		// 			libff::bit_vector root,
		// 			libff::bit_vector address_bits,
		// 			size_t address,
		// 			std::vector<merkle_authentication_node> path);

		void setup( libff::bit_vector q_input_bits,
                    libff::bit_vector PKsig_input_bits,
                    libff::bit_vector rho_input_bits,
                    libff::bit_vector root,
                    libff::bit_vector address_bits,
                    size_t address,
                    std::vector<merkle_authentication_node> path);

		void generate_random_inputs (libff::bit_vector &input_bits,
					libff::bit_vector &root,
					libff::bit_vector &address_bits,
					size_t &address,
					std::vector<merkle_authentication_node> &path);

	protected:
		const size_t tree_depth;

	};


template<typename FieldT, typename HashT, typename ppT>
class TransCircuit : public Circuit<FieldT, HashT, ppT>
	{
	public:
		TransCircuit(const std::string& name, const size_t tree_depth);
		void setup (libff::bit_vector root,
                    libff::bit_vector cm_new,
                    libff::bit_vector eol_old,
                    libff::bit_vector q_input_bits_old,
                    libff::bit_vector PKsig_input_bits_old,
                    libff::bit_vector rho_input_bits_old,
                    libff::bit_vector q_input_bits_new,
                    libff::bit_vector PKsig_input_bits_new,
                    libff::bit_vector rho_input_bits_new,
                    libff::bit_vector address_bits,
                    size_t address,
                    std::vector<merkle_authentication_node> path);

		void generate_random_inputs (
                    libff::bit_vector &root,
                    libff::bit_vector &cm_new,
                    libff::bit_vector &eol_old,
                    libff::bit_vector &input_bits_old,
                    libff::bit_vector &input_bits_new,
                    libff::bit_vector &address_bits,
                    size_t &address,
                    std::vector<merkle_authentication_node> &path);

	protected:
		const size_t tree_depth;

	};

template<typename FieldT, typename HashT, typename ppT>
class MergeCircuit : public Circuit<FieldT, HashT, ppT>
	{
	public:
		MergeCircuit(const std::string& name, const size_t tree_depth);
		void setup (libff::bit_vector root,
                    libff::bit_vector cm_new,
                    libff::bit_vector eol_old_1,
                    libff::bit_vector eol_old_2,
                    libff::bit_vector q_input_bits_old_1,
                    libff::bit_vector PKsig_input_bits_old_1,
                    libff::bit_vector rho_input_bits_old_1,
                    libff::bit_vector q_input_bits_old_2,
                    libff::bit_vector PKsig_input_bits_old_2,
                    libff::bit_vector rho_input_bits_old_2,
                    libff::bit_vector q_input_bits_new,
                    libff::bit_vector PKsig_input_bits_new,
                    libff::bit_vector rho_input_bits_new,
                    libff::bit_vector address_bits_1,
                    size_t address_1,
                    std::vector<merkle_authentication_node> path_1,
                    libff::bit_vector address_bits_2,
                    size_t address_2,
                    std::vector<merkle_authentication_node> path_2);

		void generate_random_inputs (
                    libff::bit_vector &root,
                    libff::bit_vector &cm_new,
                    libff::bit_vector &eol_old_1,
                    libff::bit_vector &eol_old_2,
                    libff::bit_vector &q_input_bits_old_1,
                    libff::bit_vector &PKsig_input_bits_old_1,
                    libff::bit_vector &rho_input_bits_old_1,
                    libff::bit_vector &q_input_bits_old_2,
                    libff::bit_vector &PKsig_input_bits_old_2,
                    libff::bit_vector &rho_input_bits_old_2,
                    libff::bit_vector &q_input_bits_new,
                    libff::bit_vector &PKsig_input_bits_new,
                    libff::bit_vector &rho_input_bits_new,
                    libff::bit_vector &address_bits_1,
                    size_t &address_1,
                    std::vector<merkle_authentication_node> &path_1,
                    libff::bit_vector &address_bits_2,
                    size_t &address_2,
                    std::vector<merkle_authentication_node> &path_2);

	protected:
		const size_t tree_depth;

	};



#include "circuit.tcc"
#endif