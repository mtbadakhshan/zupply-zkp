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

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"

using namespace libsnark;

template<typename FieldT, typename HashT, typename ppT>
class Circuit
	{
	public:
		const std::string name;
		Circuit(const std::string& name) : name(name) {};
		// virtual r1cs_ppzksnark_keypair<ppT> trusted_setup() = 0;


	protected:
		protoboard<FieldT> pb;
		std::vector<gadget<FieldT>> gadgets;
	};


template<typename FieldT, typename HashT, typename ppT>
class AuthCircuit : public Circuit<FieldT, HashT, ppT>
	{
	public:
		AuthCircuit(const std::string& name) ;
		// r1cs_ppzksnark_keypair<ppT> trusted_setup() {};

	};

#include "circuit.tcc"
#endif