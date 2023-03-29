// #ifndef CIRCUIT_CPP
// #define CIRCUIT_CPP

#include "circuit.hpp"

template<typename FieldT, typename HashT, typename ppT>
AuthCircuit<FieldT, HashT, ppT>::AuthCircuit(const std::string& name):Circuit<FieldT, HashT, ppT>(name) 
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
}

// #endif