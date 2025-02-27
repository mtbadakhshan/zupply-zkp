/** @file
 *****************************************************************************
 * @author     This file is part of Zupply, developed by Mohammadtaghi Badakhshan
 *
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef CIRCUIT_HPP
#error "utils.tcc should not be included directly. Include utils.hpp instead."
#endif

#include "circuit.hpp"

/* ====================================================================================================================== */
/* -------- AuthCircuit ------------------------------------------------------------------------------------------------- */
/* ====================================================================================================================== */
template <typename FieldT, typename HashT, typename ppT>
AuthCircuit<FieldT, HashT, ppT>::AuthCircuit(const std::string &name, const size_t tree_depth) : Circuit<FieldT, HashT, ppT>(name, tree_depth)
{

    std::cout << "/* --- AuthCircuit --- */" << std::endl;

    const size_t q_len = 64;
    const size_t PKsig_len = 256;
    const size_t rho_len = 192;

    libff::bit_vector input_bits(HashT::get_block_len());
    libff::bit_vector root(HashT::get_digest_len());
    libff::bit_vector address_bits;
    size_t address;
    std::vector<merkle_authentication_node> path(tree_depth);

    generate_random_inputs(input_bits, root, address_bits, address, path);

    libff::bit_vector q_input_bits(input_bits.begin(), input_bits.begin() + q_len);
    libff::bit_vector PKsig_input_bits(input_bits.begin() + q_len, input_bits.begin() + q_len + PKsig_len);
    libff::bit_vector rho_input_bits(input_bits.begin() + q_len + PKsig_len, input_bits.begin() + q_len + PKsig_len + rho_len);

    setup(q_input_bits, PKsig_input_bits, rho_input_bits, root, address_bits, address, path);
}

/* --- SETUP --- */
template <typename FieldT, typename HashT, typename ppT>
void AuthCircuit<FieldT, HashT, ppT>::setup(
    libff::bit_vector q_input_bits,
    libff::bit_vector PKsig_input_bits,
    libff::bit_vector rho_input_bits,
    libff::bit_vector root,
    libff::bit_vector address_bits,
    size_t address,
    std::vector<merkle_authentication_node> path)
{

    std::cout << "/* --- SETUP --- */" << std::endl;
    const size_t digest_len = HashT::get_digest_len();
    const size_t q_len = 64;
    const size_t PKsig_len = 256;
    const size_t rho_len = 192;
    const size_t tree_depth = this->tree_depth;


    /* Make a Protoboard */
    protoboard<FieldT> pb;

    /* Public Inputs */

    pb_variable<FieldT> root_128bit_1;
    pb_variable<FieldT> root_128bit_2;
    root_128bit_1.allocate(pb, "root_128bit_part1");
    root_128bit_2.allocate(pb, "root_128bit_part2");

    /* Dummy Public Inputs for Aurora */
    pb_variable_array<FieldT> dummy_variables;
    dummy_variables.allocate(pb, 1, "dummy_variables"); // Size is 2^2 - #number_of_public_inputs(=2) - 1 = 1


    /* Connecting Public inputs */

    digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");

    linear_combination<FieldT> root_128bit_lc_1, root_128bit_lc_2;

    for (size_t i = 0; i < 128; ++i)
    {
        root_128bit_lc_1.add_term(root_digest.bits[i], libff::power<FieldT>(2, i));
        root_128bit_lc_2.add_term(root_digest.bits[i + 128], libff::power<FieldT>(2, i));
    }

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(root_128bit_lc_1, FieldT::one(), root_128bit_1), "Root part 1 Constraints");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(root_128bit_lc_2, FieldT::one(), root_128bit_2), "Root part 2 Constraints");

    /* Private Inputs */
    pb_variable_array<FieldT> q_input;
    q_input.allocate(pb, q_len, "q_input");
    // ---
    pb_variable_array<FieldT> PKsig_input;
    PKsig_input.allocate(pb, PKsig_len, "PKsig_input");
    // ---
    pb_variable_array<FieldT> rho_input;
    rho_input.allocate(pb, rho_len, "rho_input");

    std::vector<pb_variable_array<FieldT>> input_parts;
    input_parts.push_back(q_input);
    input_parts.push_back(PKsig_input);
    input_parts.push_back(rho_input);

    // block_variable<FieldT> input(pb, SHA256_block_size, "input"); //It's "q", "PK_sig", rho
    block_variable<FieldT> input(pb, input_parts, "input"); // It's "q", "PK_sig", rho

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
    pb.set_input_sizes(2);

    std::cout << "/* --- Trusted Setup : Generating the CRS (keypar) --- */" << std::endl;
    /* Trusted Setup : Generating the CRS (keypar) */

    crh.generate_r1cs_constraints();
    path_var.generate_r1cs_constraints();
    ml.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(constraint_system);

    // Warning: check that the assignment operation is implemented correctly - avoid shallow copy
    this->keypair.pk = keypair.pk;
    this->keypair.vk = keypair.vk;

    const size_t num_constraints = pb.num_constraints();
    const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth) + sha256_two_to_one_hash_gadget<FieldT>::expected_constraints(SHA256_block_size) + 2;
    assert(num_constraints == expected_constraints);

    if (num_constraints != expected_constraints)
    {
        std::cerr << "num_constraints:" << num_constraints << ",  expected_constraints:" << expected_constraints << std::endl;
        return;
    }

    std::cout << "Setup done - num_constraints:" << num_constraints << std::endl;

    std::cout << "/* --- Witness Generation --- */" << std::endl;

    /* Witness Generation according to the function's input parameters */

    libff::bit_vector input_bits(q_input_bits);
    // input_bits.insert(input_bits.end(), q_input_bits.begin(), q_input_bits.end());
    input_bits.insert(input_bits.end(), PKsig_input_bits.begin(), PKsig_input_bits.end());
    input_bits.insert(input_bits.end(), rho_input_bits.begin(), rho_input_bits.end());

    libff::bit_vector leaf = HashT::get_hash(input_bits);

    for (size_t i = 0; i < 128; ++i)
    {
        pb.val(root_128bit_1) += root[i] ? libff::power<FieldT>(2, i) : 0;
        pb.val(root_128bit_2) += root[i + 128] ? libff::power<FieldT>(2, i) : 0;
    }

    // for (size_t i = 0; i < 256; ++i)
    // {
    //     pb.val(root_256bit) += root[i] ? libff::power<FieldT>(2, i) : 0;
    //     // pb.val(root_128bit_2) += root[i + 128] ? libff::power<FieldT>(2, i) : 0;
    // }

    // std::cout<<"root: " << root << std::endl;

    root_digest.generate_r1cs_witness(root);
    address_bits_va.fill_with_bits(pb, address_bits);
    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
    leaf_digest.generate_r1cs_witness(leaf);

    q_input.fill_with_bits(pb, q_input_bits);
    PKsig_input.fill_with_bits(pb, PKsig_input_bits);
    rho_input.fill_with_bits(pb, rho_input_bits);

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

    this->r1cs_constraints = pb.get_constraint_system();
    std::cout << "R1CS constraints are assigned!" << std::endl;
    this->primary_input = pb.primary_input();
    std::cout << "Primary inputes are assigned!" << std::endl;
    this->auxiliary_input = pb.auxiliary_input();
    std::cout << "Auxiliary inputes are assigned!" << std::endl;

}

/* --- GENERATE RANDOM INPUTS --- */
template <typename FieldT, typename HashT, typename ppT>
void AuthCircuit<FieldT, HashT, ppT>::generate_random_inputs(libff::bit_vector &input_bits,
                                                             libff::bit_vector &root,
                                                             libff::bit_vector &address_bits,
                                                             size_t &address,
                                                             std::vector<merkle_authentication_node> &path)
{
    std::cout << "/* --- GENERATE RANDOM INPUTS --- */" << std::endl;
    /* Generating random input */
    // In actual implementation it should be generated secretly and passed by the user.
    const size_t digest_len = HashT::get_digest_len();
    const size_t tree_depth = this->tree_depth;

    std::generate(input_bits.begin(), input_bits.end(), [&]()
                  { return std::rand() % 2; });
    libff::bit_vector leaf = HashT::get_hash(input_bits);
    libff::bit_vector prev_hash = leaf;
    address = 0;
    for (long level = tree_depth - 1; level >= 0; --level)
    {
        const bool computed_is_right = (std::rand() % 2);
        address |= (computed_is_right ? 1ul << (tree_depth - 1 - level) : 0);
        address_bits.push_back(computed_is_right);
        libff::bit_vector other(digest_len);
        std::generate(other.begin(), other.end(), [&]()
                      { return std::rand() % 2; });

        libff::bit_vector block = prev_hash;
        block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
        libff::bit_vector h = HashT::get_hash(block);

        path[level] = other;
        prev_hash = h;
    }
    root = prev_hash;
}
