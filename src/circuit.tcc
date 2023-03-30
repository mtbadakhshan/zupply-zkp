// #ifndef CIRCUIT_CPP
// #define CIRCUIT_CPP

#include "circuit.hpp"

template<typename FieldT, typename HashT, typename ppT>
AuthCircuit<FieldT, HashT, ppT>::AuthCircuit(const std::string& name, const size_t tree_depth):
Circuit<FieldT, HashT, ppT>(name), tree_depth(tree_depth)
{

    std::cout<< "/* --- AuthCircuit --- */" << std::endl;

    libff::bit_vector input_bits(HashT::get_block_len());
    libff::bit_vector root(HashT::get_digest_len());
    libff::bit_vector address_bits;
    size_t address;
    std::vector<merkle_authentication_node> path(tree_depth);

    generate_random_inputs(input_bits, root, address_bits, address, path);
    setup(input_bits, root, address_bits, address, path);

}

/* --- SETUP --- */
template<typename FieldT, typename HashT, typename ppT>
void AuthCircuit<FieldT, HashT, ppT>::setup(libff::bit_vector input_bits,
                    libff::bit_vector root,
                    libff::bit_vector address_bits,
                    size_t address,
                    std::vector<merkle_authentication_node> path)
{

    std::cout<< "/* --- SETUP --- */" << std::endl;
    const size_t digest_len = HashT::get_digest_len();
     
    /* Make a Protoboard */
    protoboard<FieldT> pb;
    
    /* Public Inputs */
    digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");

    /* Private Inputs */
    block_variable<FieldT> input(pb, SHA256_block_size, "input"); //It's "q", "PK_sig", rho

    /* Building the MHT */
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

    /* Trusted Setup : Generating the CRS (keypar) */
 
    crh.generate_r1cs_constraints();
    path_var.generate_r1cs_constraints();
    ml.generate_r1cs_constraints();

    /* Functional Make a Protoboard */

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(constraint_system);

    // Warning: check that the assignment operation is implemented correctly - avoid shallow copy 
    this->keypair.pk = keypair.pk;
    this->keypair.vk = keypair.vk;

    const size_t num_constraints = pb.num_constraints();
    const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth)
                                            + sha256_two_to_one_hash_gadget<FieldT>::expected_constraints(SHA256_block_size);
    assert(num_constraints == expected_constraints);

    if (num_constraints != expected_constraints){
        std::cerr <<  "num_constraints:" << num_constraints << ",  expected_constraints:" << expected_constraints << std::endl;
        return;
    }


    /* Witness Generation according to the function's input parameters */

    libff::bit_vector leaf = HashT::get_hash(input_bits);

    root_digest.generate_r1cs_witness(root);
    address_bits_va.fill_with_bits(pb, address_bits);
    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
    leaf_digest.generate_r1cs_witness(leaf);
    input.generate_r1cs_witness(input_bits);

    path_var.generate_r1cs_witness(address, path);
    ml.generate_r1cs_witness();
    crh.generate_r1cs_witness();
    

    /* make sure that read checker didn't accidentally overwrite anything */
    address_bits_va.fill_with_bits(pb, address_bits);
    leaf_digest.generate_r1cs_witness(leaf);
    root_digest.generate_r1cs_witness(root);
    input.generate_r1cs_witness(input_bits);
    assert(pb.is_satisfied());


    this->primary_input = pb.primary_input();
    this->auxiliary_input = pb.auxiliary_input();
}

/* --- GENERATE RANDOM INPUTS --- */
template<typename FieldT, typename HashT, typename ppT>
void AuthCircuit<FieldT, HashT, ppT>::generate_random_inputs (libff::bit_vector &input_bits,
                    libff::bit_vector &root,
                    libff::bit_vector &address_bits,
                    size_t &address,
                    std::vector<merkle_authentication_node> &path)
{
    std::cout<< "/* --- GENERATE RANDOM INPUTS --- */" << std::endl;
    /* Generating random input */
     // In actual implementation it should be generated secretly and passed by the user. 
    const size_t digest_len = HashT::get_digest_len();   
    std::generate(input_bits.begin(), input_bits.end(), [&]() { return std::rand() % 2; });
    libff::bit_vector leaf = HashT::get_hash(input_bits);
    libff::bit_vector prev_hash = leaf;
    std::cout<< "/* --- Done init --- */" << std::endl;
    address = 0;
    for (long level = tree_depth-1; level >= 0; --level)
    {
        std::cout<< "level = " << level << std::endl;
        const bool computed_is_right = (std::rand() % 2);
        address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
        address_bits.push_back(computed_is_right);
        libff::bit_vector other(digest_len);
        std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

        libff::bit_vector block = prev_hash;
        block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
        libff::bit_vector h = HashT::get_hash(block);

        std::cout<< "end - level = " << level << std::endl;

        path[level] = other;
        prev_hash = h;
    }
    root = prev_hash;
}

// #endif