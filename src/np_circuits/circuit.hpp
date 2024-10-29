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
        linear_combination<FieldT> a_lc, b_lc;
        for (size_t i = 0; i < a.size(); ++i) {
            a_lc.add_term(a[i], libff::power<FieldT>(2, a.size()-i-1));
            b_lc.add_term(b[i], libff::power<FieldT>(2, a.size()-i-1));
        }
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(a_lc, FieldT::one(), b_lc), "a = b");
    }
};


template<typename FieldT>
class is_sum_equal_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> a;
    pb_variable_array<FieldT> b;
    pb_variable_array<FieldT> c;

    is_sum_equal_gadget(protoboard<FieldT>& pb,
            const pb_variable_array<FieldT>& a_,
            const pb_variable_array<FieldT>& b_,
            const pb_variable_array<FieldT>& c_,
            const std::string& annotation_prefix = "")
        : gadget<FieldT>(pb, annotation_prefix), a(a_), b(b_), c(c_)//, carry(carry_)
    {
        assert(a.size() == b.size());
        assert(a.size() == c.size());
    }

    void generate_r1cs_constraints() {
        linear_combination<FieldT> sum_lc, c_lc;
        for (size_t i = 0; i < a.size(); ++i) {
            sum_lc.add_term(a[i], libff::power<FieldT>(2, a.size()-i-1));
            sum_lc.add_term(b[i], libff::power<FieldT>(2, a.size()-i-1));
            c_lc.add_term(  c[i], libff::power<FieldT>(2, a.size()-i-1));
        }
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sum_lc, FieldT::one(), c_lc), "a + b = c");
    }
};


template<typename FieldT, typename HashT, typename ppT>
class Circuit
	{
	public:
		const std::string name;
		Circuit(const std::string& name, const size_t tree_depth) : name(name), tree_depth(tree_depth) {}
		r1cs_gg_ppzksnark_keypair<ppT> get_keypair() { return keypair; }
		r1cs_primary_input<FieldT> get_primary_input() { return primary_input; }
		r1cs_auxiliary_input<FieldT> get_auxiliary_input() { return auxiliary_input; }
        r1cs_constraint_system<FieldT> get_r1cs_constraints() { return r1cs_constraints; }

	protected:
        r1cs_constraint_system<FieldT> r1cs_constraints;
		r1cs_gg_ppzksnark_keypair<ppT> keypair;
		r1cs_primary_input<FieldT> primary_input;
		r1cs_auxiliary_input<FieldT> auxiliary_input;
		const size_t tree_depth;
	};


template<typename FieldT, typename HashT, typename ppT>
class AuthCircuit : public Circuit<FieldT, HashT, ppT>
	{
	public:
		AuthCircuit(const std::string& name, const size_t tree_depth);

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
	};



template<typename FieldT, typename HashT, typename ppT>
class DivCircuit : public Circuit<FieldT, HashT, ppT>
	{
	public:
		DivCircuit(const std::string& name, const size_t tree_depth);
		void setup (libff::bit_vector root,
                    libff::bit_vector cm_new_1,
                    libff::bit_vector cm_new_2,
                    libff::bit_vector eol_old,
                    libff::bit_vector q_input_bits_old,
                    libff::bit_vector PKsig_input_bits_old,
                    libff::bit_vector rho_input_bits_old,
                    libff::bit_vector q_input_bits_new_1,
                    libff::bit_vector PKsig_input_bits_new_1,
                    libff::bit_vector rho_input_bits_new_1,
                    libff::bit_vector q_input_bits_new_2,
                    libff::bit_vector PKsig_input_bits_new_2,
                    libff::bit_vector rho_input_bits_new_2,
                    libff::bit_vector address_bits,
                    size_t address,
                    std::vector<merkle_authentication_node> path);

		void generate_random_inputs ( libff::bit_vector &root,
                    libff::bit_vector &cm_new_1,
                    libff::bit_vector &cm_new_2,
                    libff::bit_vector &eol_old,
                    libff::bit_vector &q_input_bits_old,
                    libff::bit_vector &PKsig_input_bits_old,
                    libff::bit_vector &rho_input_bits_old,
                    libff::bit_vector &q_input_bits_new_1,
                    libff::bit_vector &PKsig_input_bits_new_1,
                    libff::bit_vector &rho_input_bits_new_1,
                    libff::bit_vector &q_input_bits_new_2,
                    libff::bit_vector &PKsig_input_bits_new_2,
                    libff::bit_vector &rho_input_bits_new_2,
                    libff::bit_vector &address_bits,
                    size_t &address,
                    std::vector<merkle_authentication_node> &path);
	};



// #include "circuit.tcc"
#include "auth_circuit.tcc"
#include "trans_circuit.tcc"
#include "merge_circuit.tcc"
#include "div_circuit.tcc"
#endif