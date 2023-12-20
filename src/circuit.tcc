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
AuthCircuit<FieldT, HashT, ppT>::AuthCircuit(const std::string &name, const size_t tree_depth) : Circuit<FieldT, HashT, ppT>(name), tree_depth(tree_depth)
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

    /* Make a Protoboard */
    protoboard<FieldT> pb;

    /* Public Inputs */

    pb_variable<FieldT> root_128bit_1;
    pb_variable<FieldT> root_128bit_2;
    root_128bit_1.allocate(pb, "root_128bit_part1");
    root_128bit_2.allocate(pb, "root_128bit_part2");


    // pb_variable<FieldT> root_256bit;
    // root_256bit.allocate(pb, "root_256bit");

    /* Connecting Public inputs */

    digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");

    // linear_combination<FieldT> root_256bit_lc;
    // for (size_t i = 0; i < 256; ++i)
    // {
    //     root_256bit_lc.add_term(root_digest.bits[i], libff::power<FieldT>(2, i));
    // }

    // pb.add_r1cs_constraint(r1cs_constraint<FieldT>(root_256bit_lc, FieldT::one(), root_256bit), "Root part 1 Constraints");

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

    this->primary_input = pb.primary_input();
    this->auxiliary_input = pb.auxiliary_input();
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

/* ====================================================================================================================== */
/* -------- TransCircuit ------------------------------------------------------------------------------------------------ */
/* ====================================================================================================================== */
template <typename FieldT, typename HashT, typename ppT>
TransCircuit<FieldT, HashT, ppT>::TransCircuit(const std::string &name, const size_t tree_depth) : Circuit<FieldT, HashT, ppT>(name), tree_depth(tree_depth)
{

    std::cout << "/* --- TransCircuit --- */" << std::endl;

    const size_t q_len = 64;
    const size_t PKsig_len = 256;
    const size_t rho_len = 192;

    // public inputs
    libff::bit_vector root(HashT::get_digest_len());
    libff::bit_vector cm_new(HashT::get_digest_len());
    libff::bit_vector eol_old(HashT::get_digest_len());

    // private inputs
    libff::bit_vector input_bits_old(HashT::get_block_len());
    libff::bit_vector input_bits_new(HashT::get_block_len());
    libff::bit_vector address_bits;
    size_t address;
    std::vector<merkle_authentication_node> path(tree_depth);

    generate_random_inputs(root, cm_new, eol_old, input_bits_old, input_bits_new, address_bits, address, path);

    libff::bit_vector q_input_bits_old(input_bits_old.begin(), input_bits_old.begin() + q_len);
    libff::bit_vector PKsig_input_bits_old(input_bits_old.begin() + q_len, input_bits_old.begin() + q_len + PKsig_len);
    libff::bit_vector rho_input_bits_old(input_bits_old.begin() + q_len + PKsig_len, input_bits_old.begin() + q_len + PKsig_len + rho_len);

    libff::bit_vector q_input_bits_new(input_bits_new.begin(), input_bits_new.begin() + q_len);
    libff::bit_vector PKsig_input_bits_new(input_bits_new.begin() + q_len, input_bits_new.begin() + q_len + PKsig_len);
    libff::bit_vector rho_input_bits_new(input_bits_new.begin() + q_len + PKsig_len, input_bits_new.begin() + q_len + PKsig_len + rho_len);

    setup(root, cm_new, eol_old, q_input_bits_old, PKsig_input_bits_old,
          rho_input_bits_old, q_input_bits_new, PKsig_input_bits_new,
          rho_input_bits_new, address_bits, address, path);
}

/* --- SETUP --- */
template <typename FieldT, typename HashT, typename ppT>
void TransCircuit<FieldT, HashT, ppT>::setup(
    libff::bit_vector root,
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
    std::vector<merkle_authentication_node> path)
{

    std::cout << "/* --- SETUP --- */" << std::endl;
    const size_t digest_len = HashT::get_digest_len();
    const size_t q_len = 64;
    const size_t PKsig_len = 256;
    const size_t rho_len = 192;
    // const size_t block_len = HashT::get_block_len();

    /* Make a Protoboard */
    protoboard<FieldT> pb;

    /* Public Inputs */
    // root
    pb_variable<FieldT> root_128bit_1;
    pb_variable<FieldT> root_128bit_2;
    root_128bit_1.allocate(pb, "root_128bit_part1");
    root_128bit_2.allocate(pb, "root_128bit_part2");

    // cm_new
    pb_variable<FieldT> cm_new_128bit_1;
    pb_variable<FieldT> cm_new_128bit_2;
    cm_new_128bit_1.allocate(pb, "cm_new_128bit_part1");
    cm_new_128bit_2.allocate(pb, "cm_new_128bit_part2");

    // eol_old
    pb_variable<FieldT> eol_old_128bit_1;
    pb_variable<FieldT> eol_old_128bit_2;
    eol_old_128bit_1.allocate(pb, "eol_old_128bit_part1");
    eol_old_128bit_2.allocate(pb, "eol_old_128bit_part2");

    /* Connecting Public inputs */
    digest_variable<FieldT> root_digest(pb, digest_len, "root_digest");
    digest_variable<FieldT> cm_new_digest(pb, digest_len, "cm_new_digest");
    digest_variable<FieldT> eol_old_digest(pb, digest_len, "eol_old_digest");

    linear_combination<FieldT> root_128bit_lc_1, root_128bit_lc_2;
    linear_combination<FieldT> cm_new_128bit_lc_1, cm_new_128bit_lc_2;
    linear_combination<FieldT> eol_old_128bit_lc_1, eol_old_128bit_lc_2;

    for (size_t i = 0; i < 128; ++i)
    {
        root_128bit_lc_1.add_term(root_digest.bits[i], libff::power<FieldT>(2, i));
        root_128bit_lc_2.add_term(root_digest.bits[i + 128], libff::power<FieldT>(2, i));

        cm_new_128bit_lc_1.add_term(cm_new_digest.bits[i], libff::power<FieldT>(2, i));
        cm_new_128bit_lc_2.add_term(cm_new_digest.bits[i + 128], libff::power<FieldT>(2, i));

        eol_old_128bit_lc_1.add_term(eol_old_digest.bits[i], libff::power<FieldT>(2, i));
        eol_old_128bit_lc_2.add_term(eol_old_digest.bits[i + 128], libff::power<FieldT>(2, i));
    }

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(root_128bit_lc_1, FieldT::one(), root_128bit_1), "Root part 1 Constraints");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(root_128bit_lc_2, FieldT::one(), root_128bit_2), "Root part 2 Constraints");

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(cm_new_128bit_lc_1, FieldT::one(), cm_new_128bit_1), "cm_new part 1 Constraints");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(cm_new_128bit_lc_2, FieldT::one(), cm_new_128bit_2), "cm_new part 2 Constraints");

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(eol_old_128bit_lc_1, FieldT::one(), eol_old_128bit_1), "eol_old part 1 Constraints");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(eol_old_128bit_lc_2, FieldT::one(), eol_old_128bit_2), "eol_old part 2 Constraints");

    /* Private Inputs */
    // old cm inputs
    pb_variable_array<FieldT> q_input_old;
    q_input_old.allocate(pb, q_len, "q_input_old");
    // ---
    pb_variable_array<FieldT> PKsig_input_old;
    PKsig_input_old.allocate(pb, PKsig_len, "PKsig_input_old");
    // ---
    pb_variable_array<FieldT> rho_input_old;
    rho_input_old.allocate(pb, rho_len, "rho_input_old");

    std::vector<pb_variable_array<FieldT>> input_old_parts;
    input_old_parts.push_back(q_input_old);
    input_old_parts.push_back(PKsig_input_old);
    input_old_parts.push_back(rho_input_old);

    // new cm inputs
    pb_variable_array<FieldT> q_input_new;
    q_input_new.allocate(pb, q_len, "q_input_new");
    // ---
    pb_variable_array<FieldT> PKsig_input_new;
    PKsig_input_new.allocate(pb, PKsig_len, "PKsig_input_new");
    // ---
    pb_variable_array<FieldT> rho_input_new;
    rho_input_new.allocate(pb, rho_len, "rho_input_new");

    std::vector<pb_variable_array<FieldT>> input_new_parts;
    input_new_parts.push_back(q_input_new);
    input_new_parts.push_back(PKsig_input_new);
    input_new_parts.push_back(rho_input_new);

    pb_variable_array<FieldT> zero_padding_rho;
    zero_padding_rho.allocate(pb, SHA256_block_size - rho_len, "zero_padding_rho");

    std::vector<pb_variable_array<FieldT>> input_for_eol_crh_parts;
    input_for_eol_crh_parts.push_back(zero_padding_rho);
    input_for_eol_crh_parts.push_back(rho_input_old);

    block_variable<FieldT> input_old(pb, input_old_parts, "input_old");                         // It's "q", "PK_sig", "rho"
    block_variable<FieldT> input_new(pb, input_new_parts, "input_new");                         // It's "q", "PK_sig", "rho"
    block_variable<FieldT> input_for_eol_crh(pb, input_for_eol_crh_parts, "input_for_eol_crh"); // It's "0000...0000", "rho"

    /* Building the comparator */
    // q_input_old == q_input_new
    is_equal_gadget<FieldT> comparator(pb, q_input_old, q_input_new, "comparator");

    /* Building the MHT */
    pb_variable_array<FieldT> address_bits_va;
    address_bits_va.allocate(pb, tree_depth, "address_bits");
    digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
    merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
    merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

    /* Building CRH to get commitment  old cm */
    sha256_two_to_one_hash_gadget<FieldT> crh_old(pb, SHA256_block_size, input_old, leaf_digest, "crh_old");
    sha256_two_to_one_hash_gadget<FieldT> crh_new(pb, SHA256_block_size, input_new, cm_new_digest, "crh_new");
    sha256_two_to_one_hash_gadget<FieldT> crh_eol(pb, SHA256_block_size, input_for_eol_crh, eol_old_digest, "crh_eol_old");

    /* Setting the public input*/
    // The first 3*2 128-bit numbers are assigned to the protoboard which are root_digest, cm_new_digest and eol_old_digest
    // These are determined as public inputs */
    pb.set_input_sizes(2 * 3);

    std::cout << "/* --- Trusted Setup : Generating the CRS (keypar) --- */" << std::endl;
    /* Trusted Setup : Generating the CRS (keypar) */

    comparator.generate_r1cs_constraints();
    crh_old.generate_r1cs_constraints();
    crh_new.generate_r1cs_constraints();
    crh_eol.generate_r1cs_constraints();
    path_var.generate_r1cs_constraints();
    ml.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(constraint_system);

    // Warning: check that the assignment operation is implemented correctly - avoid shallow copy
    this->keypair.pk = keypair.pk;
    this->keypair.vk = keypair.vk;

    const size_t num_constraints = pb.num_constraints();
    const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth) + sha256_two_to_one_hash_gadget<FieldT>::expected_constraints(SHA256_block_size) + sha256_two_to_one_hash_gadget<FieldT>::expected_constraints(SHA256_block_size) + sha256_two_to_one_hash_gadget<FieldT>::expected_constraints(SHA256_block_size) + 64 + 6; // for the comparison
    assert(num_constraints == expected_constraints);

    if (num_constraints != expected_constraints)
    {
        std::cerr << "num_constraints:" << num_constraints << ",  expected_constraints:" << expected_constraints << std::endl;
        return;
    }

    std::cout << "Setup done - num_constraints:" << num_constraints << std::endl;

    std::cout << "/* --- Witness Generation --- */" << std::endl;

    // /* Witness Generation according to the function's input parameters */

    q_input_old.fill_with_bits(pb, q_input_bits_old);
    PKsig_input_old.fill_with_bits(pb, PKsig_input_bits_old);
    rho_input_old.fill_with_bits(pb, rho_input_bits_old);

    q_input_new.fill_with_bits(pb, q_input_bits_new);
    PKsig_input_new.fill_with_bits(pb, PKsig_input_bits_new);
    rho_input_new.fill_with_bits(pb, rho_input_bits_new);

    libff::bit_vector input_bits_old(q_input_bits_old);
    input_bits_old.insert(input_bits_old.end(), PKsig_input_bits_old.begin(), PKsig_input_bits_old.end());
    input_bits_old.insert(input_bits_old.end(), rho_input_bits_old.begin(), rho_input_bits_old.end());

    libff::bit_vector input_bits_new(q_input_bits_new);
    input_bits_new.insert(input_bits_new.end(), PKsig_input_bits_new.begin(), PKsig_input_bits_new.end());
    input_bits_new.insert(input_bits_new.end(), rho_input_bits_new.begin(), rho_input_bits_new.end());

    libff::bit_vector zero_padding_rho_bits(SHA256_block_size - rho_len, 0);
    libff::bit_vector input_for_eol_crh_bits(zero_padding_rho_bits);
    input_for_eol_crh_bits.insert(input_for_eol_crh_bits.end(), rho_input_bits_old.begin(), rho_input_bits_old.end());

    libff::bit_vector leaf_cm_old_bits = HashT::get_hash(input_bits_old);

    for (size_t i = 0; i < 128; ++i)
    {
        pb.val(root_128bit_1) += root[i] ? libff::power<FieldT>(2, i) : 0;
        pb.val(root_128bit_2) += root[i + 128] ? libff::power<FieldT>(2, i) : 0;

        pb.val(cm_new_128bit_1) += cm_new[i] ? libff::power<FieldT>(2, i) : 0;
        pb.val(cm_new_128bit_2) += cm_new[i + 128] ? libff::power<FieldT>(2, i) : 0;

        pb.val(eol_old_128bit_1) += eol_old[i] ? libff::power<FieldT>(2, i) : 0;
        pb.val(eol_old_128bit_2) += eol_old[i + 128] ? libff::power<FieldT>(2, i) : 0;
    }

    root_digest.generate_r1cs_witness(root);
    cm_new_digest.generate_r1cs_witness(cm_new);
    eol_old_digest.generate_r1cs_witness(eol_old);

    //  // DEBUGING
    //     std::cout<<"DEBUGING"<<std::endl;
    //     std::cout<< "root_digest:" << std::endl;
    //     for(size_t i=0; i < digest_len; i++)
    //         std::cout<<root[i];
    //     // std::cout<< "root:" <<root << std::endl;
    //     std::cout<<"END of DEBUGING"<<std::endl;
    // // END of DEBUGING

    address_bits_va.fill_with_bits(pb, address_bits);
    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
    leaf_digest.generate_r1cs_witness(leaf_cm_old_bits);
    input_old.generate_r1cs_witness(input_bits_old);
    input_new.generate_r1cs_witness(input_bits_new);
    input_for_eol_crh.generate_r1cs_witness(input_for_eol_crh_bits);

    path_var.generate_r1cs_witness(address, path);
    ml.generate_r1cs_witness();
    crh_old.generate_r1cs_witness();
    crh_new.generate_r1cs_witness();
    crh_eol.generate_r1cs_witness();
    
    libff::bit_vector computed_root = ml.computed_root->bits.get_bits(pb);
    if (computed_root != root){
        std::cout << "Error! ml_1" << std::endl;
        std:: cout << "computed_root: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << computed_root[i] ;
        std::cout << std::endl;

        std:: cout << "root: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << root[i] ;
        std::cout << std::endl;
    } else 
    {
        std::cout << "NO Error! ml_1" << std::endl;
    }

    // /* make sure that read checker didn't accidentally overwrite anything */
    address_bits_va.fill_with_bits(pb, address_bits);
    leaf_digest.generate_r1cs_witness(leaf_cm_old_bits);
    root_digest.generate_r1cs_witness(root);
    input_old.generate_r1cs_witness(input_bits_old);
    input_new.generate_r1cs_witness(input_bits_new);
    input_for_eol_crh.generate_r1cs_witness(input_for_eol_crh_bits);
    cm_new_digest.generate_r1cs_witness(cm_new);
    eol_old_digest.generate_r1cs_witness(eol_old);

    assert(pb.is_satisfied());

    if (!pb.is_satisfied())
    {
        std::cerr << "pb is Not Satisfied" << std::endl;
        return;
    }

    this->primary_input = pb.primary_input();
    this->auxiliary_input = pb.auxiliary_input();
}

/* --- GENERATE RANDOM INPUTS --- */
template <typename FieldT, typename HashT, typename ppT>
void TransCircuit<FieldT, HashT, ppT>::generate_random_inputs(
    libff::bit_vector &root,
    libff::bit_vector &cm_new,
    libff::bit_vector &eol_old,
    libff::bit_vector &input_bits_old,
    libff::bit_vector &input_bits_new,
    libff::bit_vector &address_bits,
    size_t &address,
    std::vector<merkle_authentication_node> &path)
{
    std::cout << "/* --- GENERATE RANDOM INPUTS --- */" << std::endl;
    /* Generating random input */
    // In actual implementation it should be generated secretly and passed by the user.
    const size_t digest_len = HashT::get_digest_len();
    const size_t q_len = 64;
    const size_t PKsig_len = 256;
    const size_t rho_len = 192;

    std::generate(input_bits_old.begin(), input_bits_old.end(), [&]()
                  { return std::rand() % 2; });

    // q (the first 64 bits) should be the same in two inputs
    int i = 0;
    std::generate(input_bits_new.begin(), input_bits_new.begin() + q_len, [&]()
                  { return input_bits_old[i++]; });
    std::generate(input_bits_new.begin() + q_len, input_bits_new.end(), [&]()
                  { return std::rand() % 2; });

    libff::bit_vector leaf = HashT::get_hash(input_bits_old);
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

    cm_new = HashT::get_hash(input_bits_new);

    libff::bit_vector rho_input_bits_old(input_bits_old.begin() + q_len + PKsig_len, input_bits_old.begin() + q_len + PKsig_len + rho_len);
    libff::bit_vector zero_padding_rho_bits(SHA256_block_size - rho_len, 0);
    rho_input_bits_old.insert(rho_input_bits_old.begin(), zero_padding_rho_bits.begin(), zero_padding_rho_bits.end());
    eol_old = HashT::get_hash(rho_input_bits_old);
}

/* ====================================================================================================================== */
/* -------- MergeCircuit ------------------------------------------------------------------------------------------------ */
/* ====================================================================================================================== */
template <typename FieldT, typename HashT, typename ppT>
MergeCircuit<FieldT, HashT, ppT>::MergeCircuit(const std::string &name, const size_t tree_depth) : Circuit<FieldT, HashT, ppT>(name), tree_depth(tree_depth)
{

    std::cout << "/* --- MergeCircuit --- */" << std::endl;

    const size_t q_len = 64;
    const size_t PKsig_len = 256;
    const size_t rho_len = 192;

    // public inputs
    libff::bit_vector root(HashT::get_digest_len());
    libff::bit_vector cm_new(HashT::get_digest_len());
    libff::bit_vector eol_old_1(HashT::get_digest_len());
    libff::bit_vector eol_old_2(HashT::get_digest_len());

    // private inputs
    libff::bit_vector q_input_bits_old_1(q_len);
    libff::bit_vector PKsig_input_bits_old_1(PKsig_len);
    libff::bit_vector rho_input_bits_old_1(rho_len);

    libff::bit_vector q_input_bits_old_2(q_len);
    libff::bit_vector PKsig_input_bits_old_2(PKsig_len);
    libff::bit_vector rho_input_bits_old_2(rho_len);

    libff::bit_vector q_input_bits_new(q_len);
    libff::bit_vector PKsig_input_bits_new(PKsig_len);
    libff::bit_vector rho_input_bits_new(rho_len);

    libff::bit_vector address_bits_1;
    size_t address_1;
    std::vector<merkle_authentication_node> path_1(tree_depth);

    libff::bit_vector address_bits_2;
    size_t address_2;
    std::vector<merkle_authentication_node> path_2(tree_depth);

    generate_random_inputs(root, cm_new, eol_old_1, eol_old_2, q_input_bits_old_1, PKsig_input_bits_old_1, rho_input_bits_old_1,
                           q_input_bits_old_2, PKsig_input_bits_old_2, rho_input_bits_old_2, q_input_bits_new,
                           PKsig_input_bits_new, rho_input_bits_new, address_bits_1, address_1, path_1, address_bits_2,
                           address_2, path_2);

    setup(root, cm_new, eol_old_1, eol_old_2, q_input_bits_old_1, PKsig_input_bits_old_1, rho_input_bits_old_1,
          q_input_bits_old_2, PKsig_input_bits_old_2, rho_input_bits_old_2, q_input_bits_new,
          PKsig_input_bits_new, rho_input_bits_new, address_bits_1, address_1, path_1, address_bits_2,
          address_2, path_2);
}

/* --- SETUP --- */
template <typename FieldT, typename HashT, typename ppT>
void MergeCircuit<FieldT, HashT, ppT>::setup(
    libff::bit_vector root,
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
    std::vector<merkle_authentication_node> path_2)
{

    std::cout << "/* --- SETUP --- */" << std::endl;
    const size_t digest_len = HashT::get_digest_len();
    const size_t q_len = 64;
    const size_t PKsig_len = 256;
    const size_t rho_len = 192;
    // const size_t block_len = HashT::get_block_len();

    /* Make a Protoboard */
    protoboard<FieldT> pb;

    // /* Public Inputs */
    digest_variable<FieldT> root_digest(pb, digest_len, "root_digest");
    digest_variable<FieldT> cm_new_digest(pb, digest_len, "cm_new_digest");
    digest_variable<FieldT> eol_old_1_digest(pb, digest_len, "eol_old_1_digest");
    digest_variable<FieldT> eol_old_2_digest(pb, digest_len, "eol_old_2_digest");

    /* Private Inputs */

    // old cm_1 inputs
    pb_variable_array<FieldT> q_input_old_1;
    q_input_old_1.allocate(pb, q_len, "q_input_old_1");
    // ---
    pb_variable_array<FieldT> PKsig_input_old_1;
    PKsig_input_old_1.allocate(pb, PKsig_len, "PKsig_input_old_1");
    // ---
    pb_variable_array<FieldT> rho_input_old_1;
    rho_input_old_1.allocate(pb, rho_len, "rho_input_old_1");

    std::vector<pb_variable_array<FieldT>> input_old_parts_1;
    input_old_parts_1.push_back(q_input_old_1);
    input_old_parts_1.push_back(PKsig_input_old_1);
    input_old_parts_1.push_back(rho_input_old_1);

    // old cm_1 inputs
    pb_variable_array<FieldT> q_input_old_2;
    q_input_old_2.allocate(pb, q_len, "q_input_old_2");
    // ---
    pb_variable_array<FieldT> PKsig_input_old_2;
    PKsig_input_old_2.allocate(pb, PKsig_len, "PKsig_input_old_2");
    // ---
    pb_variable_array<FieldT> rho_input_old_2;
    rho_input_old_2.allocate(pb, rho_len, "rho_input_old_2");

    std::vector<pb_variable_array<FieldT>> input_old_parts_2;
    input_old_parts_2.push_back(q_input_old_2);
    input_old_parts_2.push_back(PKsig_input_old_2);
    input_old_parts_2.push_back(rho_input_old_2);

    // new cm inputs
    pb_variable_array<FieldT> q_input_new;
    q_input_new.allocate(pb, q_len, "q_input_new");
    // ---
    pb_variable_array<FieldT> PKsig_input_new;
    PKsig_input_new.allocate(pb, PKsig_len, "PKsig_input_new");
    // ---
    pb_variable_array<FieldT> rho_input_new;
    rho_input_new.allocate(pb, rho_len, "rho_input_new");

    std::vector<pb_variable_array<FieldT>> input_new_parts;
    input_new_parts.push_back(q_input_new);
    input_new_parts.push_back(PKsig_input_new);
    input_new_parts.push_back(rho_input_new);

    pb_variable_array<FieldT> zero_padding_rho;
    zero_padding_rho.allocate(pb, SHA256_block_size - rho_len, "zero_padding_rho");

    std::vector<pb_variable_array<FieldT>> input_for_eol_crh_parts_1;
    input_for_eol_crh_parts_1.push_back(zero_padding_rho);
    input_for_eol_crh_parts_1.push_back(rho_input_old_1);

    std::vector<pb_variable_array<FieldT>> input_for_eol_crh_parts_2;
    input_for_eol_crh_parts_2.push_back(zero_padding_rho);
    input_for_eol_crh_parts_2.push_back(rho_input_old_2);

    block_variable<FieldT> input_old_1(pb, input_old_parts_1, "input_old_1");                         // It's "q", "PK_sig", "rho"
    block_variable<FieldT> input_old_2(pb, input_old_parts_2, "input_old_2");                         // It's "q", "PK_sig", "rho"
    block_variable<FieldT> input_new(pb, input_new_parts, "input_new");                               // It's "q", "PK_sig", "rho"
    block_variable<FieldT> input_for_eol_crh_1(pb, input_for_eol_crh_parts_1, "input_for_eol_crh_1"); // It's "0000...0000", "rho"
    block_variable<FieldT> input_for_eol_crh_2(pb, input_for_eol_crh_parts_2, "input_for_eol_crh_2"); // It's "0000...0000", "rho"

    // /* Building the comparator */
    // // q_input_old == q_input_new
    // is_equal_gadget<FieldT> comparator(pb, q_input_old, q_input_new, "comparator");

    /* Building the MHT */
    // #1
    pb_variable_array<FieldT> address_bits_va_1;
    address_bits_va_1.allocate(pb, tree_depth, "address_bits_va_1");
    digest_variable<FieldT> leaf_digest_1(pb, digest_len, "leaf_digest_1");
    merkle_authentication_path_variable<FieldT, HashT> path_var_1(pb, tree_depth, "path_var_1");
    merkle_tree_check_read_gadget<FieldT, HashT> ml_1(pb, tree_depth, address_bits_va_1, leaf_digest_1, root_digest, path_var_1, ONE, "ml");

    // #2
    pb_variable_array<FieldT> address_bits_va_2;
    address_bits_va_2.allocate(pb, tree_depth, "address_bits_va_2");
    digest_variable<FieldT> leaf_digest_2(pb, digest_len, "leaf_digest_2");
    merkle_authentication_path_variable<FieldT, HashT> path_var_2(pb, tree_depth, "path_var_2");
    merkle_tree_check_read_gadget<FieldT, HashT> ml_2(pb, tree_depth, address_bits_va_2, leaf_digest_2, root_digest, path_var_2, ONE, "ml");

    // /* Building CRH to get commitment  old cm */
    sha256_two_to_one_hash_gadget<FieldT> crh_old_1(pb, SHA256_block_size, input_old_1, leaf_digest_1, "crh_old_1");
    sha256_two_to_one_hash_gadget<FieldT> crh_old_2(pb, SHA256_block_size, input_old_2, leaf_digest_2, "crh_old_2");
    sha256_two_to_one_hash_gadget<FieldT> crh_new(pb, SHA256_block_size, input_new, cm_new_digest, "crh_new");
    sha256_two_to_one_hash_gadget<FieldT> crh_eol_1(pb, SHA256_block_size, input_for_eol_crh_1, eol_old_1_digest, "crh_eol_old_1");
    sha256_two_to_one_hash_gadget<FieldT> crh_eol_2(pb, SHA256_block_size, input_for_eol_crh_2, eol_old_2_digest, "crh_eol_old_2");

    /* Setting the public input*/
    // The first 4*256 bits assigned to the protoboard which are root_digest, cm_new_digest, eol_old_1_digest, and eol_old_2_digest
    // These are determined as public inputs */
    pb.set_input_sizes(digest_len * 4);

    std::cout << "/* --- Trusted Setup : Generating the CRS (keypar) --- */" << std::endl;
    /* Trusted Setup : Generating the CRS (keypar) */

    // comparator.generate_r1cs_constraints();
    crh_old_1.generate_r1cs_constraints();
    crh_old_2.generate_r1cs_constraints();
    crh_new.generate_r1cs_constraints();
    crh_eol_1.generate_r1cs_constraints();
    crh_eol_2.generate_r1cs_constraints();
    path_var_1.generate_r1cs_constraints();
    path_var_2.generate_r1cs_constraints();
    ml_1.generate_r1cs_constraints();
    ml_2.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(constraint_system);

    // // Warning: check that the assignment operation is implemented correctly - avoid shallow copy
    this->keypair.pk = keypair.pk;
    this->keypair.vk = keypair.vk;

    const size_t num_constraints = pb.num_constraints();
    const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth) * 2 + sha256_two_to_one_hash_gadget<FieldT>::expected_constraints(SHA256_block_size) * 5; // for the comparison
    assert(num_constraints == expected_constraints);

    if (num_constraints != expected_constraints)
    {
        std::cerr << "num_constraints:" << num_constraints << ",  expected_constraints:" << expected_constraints << std::endl;
        return;
    }

    std::cout << "Setup done - num_constraints:" << num_constraints << std::endl;

    std::cout << "/* --- Witness Generation --- */" << std::endl;

    /* Witness Generation according to the function's input parameters */

    q_input_old_1.fill_with_bits(pb, q_input_bits_old_1);
    PKsig_input_old_1.fill_with_bits(pb, PKsig_input_bits_old_1);
    rho_input_old_1.fill_with_bits(pb, rho_input_bits_old_1);

    q_input_old_2.fill_with_bits(pb, q_input_bits_old_2);
    PKsig_input_old_2.fill_with_bits(pb, PKsig_input_bits_old_2);
    rho_input_old_2.fill_with_bits(pb, rho_input_bits_old_2);

    q_input_new.fill_with_bits(pb, q_input_bits_new);
    PKsig_input_new.fill_with_bits(pb, PKsig_input_bits_new);
    rho_input_new.fill_with_bits(pb, rho_input_bits_new);

    libff::bit_vector input_bits_old_1(q_input_bits_old_1);
    input_bits_old_1.insert(input_bits_old_1.end(), PKsig_input_bits_old_1.begin(), PKsig_input_bits_old_1.end());
    input_bits_old_1.insert(input_bits_old_1.end(), rho_input_bits_old_1.begin(), rho_input_bits_old_1.end());

    libff::bit_vector input_bits_old_2(q_input_bits_old_2);
    input_bits_old_2.insert(input_bits_old_2.end(), PKsig_input_bits_old_2.begin(), PKsig_input_bits_old_2.end());
    input_bits_old_2.insert(input_bits_old_2.end(), rho_input_bits_old_2.begin(), rho_input_bits_old_2.end());

    libff::bit_vector input_bits_new(q_input_bits_new);
    input_bits_new.insert(input_bits_new.end(), PKsig_input_bits_new.begin(), PKsig_input_bits_new.end());
    input_bits_new.insert(input_bits_new.end(), rho_input_bits_new.begin(), rho_input_bits_new.end());

    libff::bit_vector zero_padding_rho_bits(SHA256_block_size - rho_len, 0);

    libff::bit_vector input_for_eol_crh_bits_1(zero_padding_rho_bits);
    input_for_eol_crh_bits_1.insert(input_for_eol_crh_bits_1.end(), rho_input_bits_old_1.begin(), rho_input_bits_old_1.end());

    libff::bit_vector input_for_eol_crh_bits_2(zero_padding_rho_bits);
    input_for_eol_crh_bits_2.insert(input_for_eol_crh_bits_2.end(), rho_input_bits_old_2.begin(), rho_input_bits_old_2.end());

    libff::bit_vector leaf_cm_old_bits_1 = HashT::get_hash(input_bits_old_1);
    libff::bit_vector leaf_cm_old_bits_2 = HashT::get_hash(input_bits_old_2);

    if (HashT::get_hash(input_bits_new) == cm_new){
        std::cout << "NO Error!" << std::endl;
        std:: cout << "cm_new: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << cm_new[i] ;
        std::cout << std::endl;

        libff::bit_vector  hash = HashT::get_hash(input_bits_new);
        std:: cout << "cm_new: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << hash[i] ;
        std::cout << std::endl;
    } else {
        std::cout << " Error!" << std::endl;
    }

    if (HashT::get_hash(input_for_eol_crh_bits_1) == eol_old_1){
        std::cout << "NO Error! on eol_old_1" << std::endl;
    }

    if (HashT::get_hash(input_for_eol_crh_bits_2) == eol_old_2){
        std::cout << "NO Error! on eol_old_2" << std::endl;
    }

    root_digest.generate_r1cs_witness(root);
    cm_new_digest.generate_r1cs_witness(cm_new);
    eol_old_1_digest.generate_r1cs_witness(eol_old_1);
    eol_old_2_digest.generate_r1cs_witness(eol_old_2);

    address_bits_va_1.fill_with_bits(pb, address_bits_1);
    address_bits_va_2.fill_with_bits(pb, address_bits_2);
    assert(address_bits_va_1.get_field_element_from_bits(pb).as_ulong() == address_1);
    assert(address_bits_va_2.get_field_element_from_bits(pb).as_ulong() == address_2);

    leaf_digest_1.generate_r1cs_witness(leaf_cm_old_bits_1);

    // if (leaf_digest_1.bits.get_bits(pb))

    std:: cout << "computed leaf_1: ";
    for (size_t i{0}; i < digest_len; i++)
        std:: cout  << leaf_digest_1.bits.get_bits(pb)[i] ;
    std::cout << std::endl;

    leaf_digest_2.generate_r1cs_witness(leaf_cm_old_bits_2);

    input_old_1.generate_r1cs_witness(input_bits_old_1);
    input_old_2.generate_r1cs_witness(input_bits_old_2);

    input_new.generate_r1cs_witness(input_bits_new);
    input_for_eol_crh_1.generate_r1cs_witness(input_for_eol_crh_bits_1);
    input_for_eol_crh_2.generate_r1cs_witness(input_for_eol_crh_bits_2);

    path_var_1.generate_r1cs_witness(address_1, path_1);
    path_var_2.generate_r1cs_witness(address_2, path_2);

    ml_1.generate_r1cs_witness();
    ml_2.generate_r1cs_witness();
    crh_old_1.generate_r1cs_witness();
    crh_old_2.generate_r1cs_witness();
    crh_new.generate_r1cs_witness();
    crh_eol_1.generate_r1cs_witness();
    crh_eol_2.generate_r1cs_witness();

    libff::bit_vector computed_root = ml_1.computed_root->bits.get_bits(pb);
    if (computed_root != root){
        std::cout << "Error! ml_1" << std::endl;
        std:: cout << "computed_root: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << computed_root[i] ;
        std::cout << std::endl;

        std:: cout << "root: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << root[i] ;
        std::cout << std::endl;
    }

    computed_root = ml_2.computed_root->bits.get_bits(pb);
    if (computed_root != root){
        std::cout << "Error! ml_2" << std::endl;
        std:: cout << "computed_root: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << computed_root[i] ;
        std::cout << std::endl;

        std:: cout << "root: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << root[i] ;
        std::cout << std::endl;
    }



    std::cout << "ml_1.computed_root.bits.get_bits()" << ml_1.computed_root->bits.get_bits(pb)[0] << std::endl;

    // // /* make sure that read checker didn't accidentally overwrite anything */
    root_digest.generate_r1cs_witness(root);
    cm_new_digest.generate_r1cs_witness(cm_new);
    eol_old_1_digest.generate_r1cs_witness(eol_old_1);
    eol_old_2_digest.generate_r1cs_witness(eol_old_2);

    address_bits_va_1.fill_with_bits(pb, address_bits_1);
    address_bits_va_2.fill_with_bits(pb, address_bits_2);

    if (address_bits_va_1.get_field_element_from_bits(pb).as_ulong() != address_1){
        std::cout << "address_bits_va_1.get_field_element_from_bits(pb).as_ulong() != address_1";
    }
    if (address_bits_va_2.get_field_element_from_bits(pb).as_ulong() != address_2){
        std::cout << "address_bits_va_2.get_field_element_from_bits(pb).as_ulong() != address_2";
    }
    assert(address_bits_va_1.get_field_element_from_bits(pb).as_ulong() == address_1);
    assert(address_bits_va_2.get_field_element_from_bits(pb).as_ulong() == address_2);

    leaf_digest_1.generate_r1cs_witness(leaf_cm_old_bits_1);
    leaf_digest_2.generate_r1cs_witness(leaf_cm_old_bits_2);

    input_old_1.generate_r1cs_witness(input_bits_old_1);
    input_old_2.generate_r1cs_witness(input_bits_old_2);

    input_new.generate_r1cs_witness(input_bits_new);
    input_for_eol_crh_1.generate_r1cs_witness(input_for_eol_crh_bits_1);
    input_for_eol_crh_2.generate_r1cs_witness(input_for_eol_crh_bits_2);

    path_var_1.generate_r1cs_witness(address_1, path_1);
    path_var_2.generate_r1cs_witness(address_2, path_2);

    assert(pb.is_satisfied());

    if (!pb.is_satisfied())
    {
        std::cerr << "pb is Not Satisfied" << std::endl;
        return;
    }

    this->primary_input = pb.primary_input();
    this->auxiliary_input = pb.auxiliary_input();
}

/* --- GENERATE RANDOM INPUTS --- */
template <typename FieldT, typename HashT, typename ppT>
void MergeCircuit<FieldT, HashT, ppT>::generate_random_inputs(
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
    std::vector<merkle_authentication_node> &path_2)
{
    std::cout << "/* --- GENERATE RANDOM INPUTS --- */" << std::endl;
    /* Generating random input */
    // In actual implementation it should be generated secretly and passed by the user.
    const size_t digest_len = HashT::get_digest_len();
    const size_t q_len = 64;
    const size_t rho_len = 192;

    q_input_bits_old_1[0] = 0; // To prevent overflow
    std::generate(q_input_bits_old_1.begin() + 1, q_input_bits_old_1.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(PKsig_input_bits_old_1.begin(), PKsig_input_bits_old_1.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(rho_input_bits_old_1.begin(), rho_input_bits_old_1.end(), [&]()
                  { return std::rand() % 2; });

    q_input_bits_old_2[0] = 0; // To prevent overflow
    std::generate(q_input_bits_old_2.begin() + 1, q_input_bits_old_2.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(PKsig_input_bits_old_2.begin(), PKsig_input_bits_old_2.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(rho_input_bits_old_2.begin(), rho_input_bits_old_2.end(), [&]()
                  { return std::rand() % 2; });

    std::generate(PKsig_input_bits_new.begin(), PKsig_input_bits_new.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(rho_input_bits_new.begin(), rho_input_bits_new.end(), [&]()
                  { return std::rand() % 2; });

    // Full Adder : q_input_bits_new = q_input_bits_old_1 + q_input_bits_old_2
    bool carry_bit = 0;
    for (size_t i = q_len - 1; i > 0; i--)
    {
        q_input_bits_new[i] = (q_input_bits_old_1[i] ^ q_input_bits_old_2[i]) ^ carry_bit;
        carry_bit = ((q_input_bits_old_1[i] ^ q_input_bits_old_2[i]) & carry_bit) | (q_input_bits_old_1[i] & q_input_bits_old_2[i]);
    }
    q_input_bits_new[0] = carry_bit;

    // std:: cout << "q_input_bits_old_1: ";
    // for (size_t i{0}; i < q_len; i++)
    //     std:: cout  << q_input_bits_old_1[i] ;
    // std::cout << std::endl;

    // std:: cout << "q_input_bits_old_2: ";
    // for (size_t i{0}; i < q_len; i++)
    //     std:: cout  << q_input_bits_old_2[i] ;
    // std::cout << std::endl;

    // std:: cout << "q_input_bits_new: ";
    // for (size_t i{0}; i < q_len; i++)
    //     std:: cout  << q_input_bits_new[i] ;
    // std::cout << std::endl;

    


    libff::bit_vector input_bits_old_1(q_input_bits_old_1);
    input_bits_old_1.insert(input_bits_old_1.end(), PKsig_input_bits_old_1.begin(), PKsig_input_bits_old_1.end());
    input_bits_old_1.insert(input_bits_old_1.end(), rho_input_bits_old_1.begin(), rho_input_bits_old_1.end());

    libff::bit_vector input_bits_old_2(q_input_bits_old_2);
    input_bits_old_2.insert(input_bits_old_2.end(), PKsig_input_bits_old_2.begin(), PKsig_input_bits_old_2.end());
    input_bits_old_2.insert(input_bits_old_2.end(), rho_input_bits_old_2.begin(), rho_input_bits_old_2.end());

    libff::bit_vector input_bits_new(q_input_bits_new);
    input_bits_new.insert(input_bits_new.end(), PKsig_input_bits_new.begin(), PKsig_input_bits_new.end());
    input_bits_new.insert(input_bits_new.end(), rho_input_bits_new.begin(), rho_input_bits_new.end());

    // Generatign the Merkle tree

    // the point where two distinct branches joins in the tree
    size_t merge_point = std::rand() % (tree_depth - 1);
    std::cout << "merge_point: " << merge_point << std::endl;

    libff::bit_vector leaf_1 = HashT::get_hash(input_bits_old_1);
    std:: cout << "leaf_1: ";
    for (size_t i{0}; i < digest_len; i++)
        std:: cout  << leaf_1[i] ;
    std::cout << std::endl;

    libff::bit_vector leaf_2 = HashT::get_hash(input_bits_old_2);

    std:: cout << "leaf_2: ";
    for (size_t i{0}; i < digest_len; i++)
        std:: cout  << leaf_2[i] ;
    std::cout << std::endl;

    address_1 = 0;
    address_2 = 0;

    // Before Merge
    libff::bit_vector prev_hash_1 = leaf_1;
    libff::bit_vector prev_hash_2 = leaf_2;

    for (size_t level = tree_depth - 1; level > merge_point; --level)
    {
        const bool computed_is_right_1 = (std::rand() % 2);
        const bool computed_is_right_2 = (std::rand() % 2);

        address_1 |= (computed_is_right_1 ? 1ul << (tree_depth - 1 - level) : 0);
        address_2 |= (computed_is_right_2 ? 1ul << (tree_depth - 1 - level) : 0);

        address_bits_1.push_back(computed_is_right_1);
        address_bits_2.push_back(computed_is_right_2);

        libff::bit_vector other_1(digest_len);
        libff::bit_vector other_2(digest_len);

        std::generate(other_1.begin(), other_1.end(), [&]()
                      { return std::rand() % 2; });
        std::generate(other_2.begin(), other_2.end(), [&]()
                      { return std::rand() % 2; });

        libff::bit_vector block_1 = prev_hash_1;
        libff::bit_vector block_2 = prev_hash_2;

        block_1.insert(computed_is_right_1 ? block_1.begin() : block_1.end(), other_1.begin(), other_1.end());
        block_2.insert(computed_is_right_2 ? block_2.begin() : block_2.end(), other_2.begin(), other_2.end());

        libff::bit_vector h_1 = HashT::get_hash(block_1);
        libff::bit_vector h_2 = HashT::get_hash(block_2);

        path_1[level] = other_1;
        path_2[level] = other_2;

        prev_hash_1 = h_1;
        prev_hash_2 = h_2;
    }

    // std::cout<<"Here"<<std::endl;

    // Merging - The first branch comes from left and the second branch comes from right
    const bool computed_is_right_1 = false;
    const bool computed_is_right_2 = true;
    address_1 |= (computed_is_right_1 ? 1ul << (tree_depth - 1 - merge_point) : 0);
    address_2 |= (computed_is_right_2 ? 1ul << (tree_depth - 1 - merge_point) : 0);
    address_bits_1.push_back(computed_is_right_1);
    address_bits_2.push_back(computed_is_right_2);

    path_1[merge_point] = prev_hash_2;
    path_2[merge_point] = prev_hash_1;

    libff::bit_vector block_merge = prev_hash_1;
    block_merge.insert(block_merge.begin(), prev_hash_2.begin(), prev_hash_2.end());

    libff::bit_vector prev_hash = HashT::get_hash(block_merge);

    // std::cout<<"merge_point: "<< merge_point <<std::endl;

    // Merged Branch
    for (long level = merge_point - 1; level >= 0; --level)
    {
        // std::cout<<level<<std::endl;
        const bool computed_is_right = (std::rand() % 2);

        address_1 |= (computed_is_right ? 1ul << (tree_depth - 1 - level) : 0);
        address_2 |= (computed_is_right ? 1ul << (tree_depth - 1 - level) : 0);

        address_bits_1.push_back(computed_is_right);
        address_bits_2.push_back(computed_is_right);

        libff::bit_vector other(digest_len);
        std::generate(other.begin(), other.end(), [&]()
                      { return std::rand() % 2; });

        libff::bit_vector block = prev_hash;
        block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
        libff::bit_vector h = HashT::get_hash(block);

        path_1[level] = other;
        path_2[level] = other;

        prev_hash = h;
        std::cout<<level<<std::endl;
    }

    std:: cout << "address_bits_1: ";
    for (size_t i{0}; i < tree_depth; i++)
        std:: cout  << address_bits_1[i] ;
    std::cout << std::endl;
    std:: cout  << "address_1: " << address_1 << std::endl ;

    std:: cout << "address_bits_2: ";
    for (size_t i{0}; i < tree_depth; i++)
        std:: cout  << address_bits_2[i] ;
    std::cout << std::endl;
    std:: cout  << "address_2: " << address_2 << std::endl ;


    std:: cout << "path_1: ";
    for (size_t i{0}; i < tree_depth; i++)
        {
            std:: cout  << i << ": ";
            for (size_t j{0}; j < path_1[i].size(); j++)
            std:: cout  << path_1[i][j] ;
        std::cout << std::endl;
        }
    std::cout << std::endl;

     std:: cout << "path_2: ";
    for (size_t i{0}; i < tree_depth; i++)
        {
            std:: cout  << i << ": ";
            for (size_t j{0}; j < path_2[i].size(); j++)
            std:: cout  << path_2[i][j];
        std::cout << std::endl;
        }
    std::cout << std::endl;

    // std::cout << "address_bits_1: " << address_bits_1 << std::endl;
    // std::cout << "address_bits_2: " << address_bits_2 << std::endl;


    root = prev_hash;

    std:: cout << "root: ";
    for (size_t j{0}; j < digest_len; j++)
            std:: cout  << root[j];
    std::cout << std::endl;


    prev_hash_1 = leaf_1;

    for (long level = tree_depth - 1; level >= 0; level--){

        // std::cout<<"level: "<<level<<std::endl;
        libff::bit_vector block = prev_hash_1;
        bool computed_is_right = address_bits_1[level];
        block.insert(computed_is_right ? block.begin() : block.end(), path_1[level].begin(), path_1[level].end());
        libff::bit_vector h = HashT::get_hash(block);
        prev_hash_1 = h;
        // std::cout<<"level: "<<level<<std::endl;
    }
    
std:: cout << "Here! " << std::endl;
    std:: cout << "computed root: ";
    for (size_t j{0}; j < digest_len; j++)
            std:: cout  << prev_hash_1[j];
    std::cout << std::endl;


    prev_hash_2 = leaf_2;

    for (long level = tree_depth - 1; level >= 0; level--){

        // std::cout<<"level: "<<level<<std::endl;
        libff::bit_vector block = prev_hash_2;
        bool computed_is_right = address_bits_2[level];
        block.insert(computed_is_right ? block.begin() : block.end(), path_2[level].begin(), path_2[level].end());
        libff::bit_vector h = HashT::get_hash(block);
        prev_hash_2 = h;
        // std::cout<<"level: "<<level<<std::endl;
    }
    
std:: cout << "Here! " << std::endl;
    std:: cout << "computed root2: ";
    for (size_t j{0}; j < digest_len; j++)
            std:: cout  << prev_hash_2[j];
    std::cout << std::endl;


    cm_new = HashT::get_hash(input_bits_new);
    // std::cout<<"Here2"<<std::endl;

    // libff::bit_vector rho_input_bits_old(input_bits_old.begin() + q_len + PKsig_len, input_bits_old.begin() + q_len + PKsig_len + rho_len );
    // libff::bit_vector zero_padding_rho_bits(SHA256_block_size - rho_len, 0);
    // rho_input_bits_old.insert(rho_input_bits_old.begin(), zero_padding_rho_bits.begin(), zero_padding_rho_bits.end());
    // eol_old =  HashT::get_hash(rho_input_bits_old);
    
    libff::bit_vector zero_padding_rho_bits(SHA256_block_size - rho_len, 0);

    libff::bit_vector rho_input_bits_old_padded_1(zero_padding_rho_bits);
    rho_input_bits_old_padded_1.insert(rho_input_bits_old_padded_1.end(), rho_input_bits_old_1.begin(), rho_input_bits_old_1.end());

    libff::bit_vector rho_input_bits_old_padded_2(zero_padding_rho_bits);
    rho_input_bits_old_padded_2.insert(rho_input_bits_old_padded_2.end(), rho_input_bits_old_2.begin(), rho_input_bits_old_2.end());

    // libff::bit_vector rho_input_bits_old_padded_2;
    // rho_input_bits_old_padded_2.push_back(zero_padding_rho_bits);
    // rho_input_bits_old_padded_2.push_back(rho_input_bits_old_1);

    // rho_input_bits_old_1.insert(rho_input_bits_old.begin(), zero_padding_rho_bits.begin(), zero_padding_rho_bits.end());
    eol_old_1 = HashT::get_hash(rho_input_bits_old_padded_1);
    eol_old_2 = HashT::get_hash(rho_input_bits_old_padded_2);

    std:: cout << "rho_input_bits_old_padded_1: ";
    for (size_t i{0}; i < 512; i++)
        std:: cout  << rho_input_bits_old_padded_1[i] ;
    std::cout << std::endl;

    std:: cout << "eol_old_1: ";
    for (size_t i{0}; i < digest_len; i++)
        std:: cout  << eol_old_1[i] ;
    std::cout << std::endl;
    
     std:: cout << "rho_input_bits_old_padded_2: ";
    for (size_t i{0}; i < 512; i++)
        std:: cout  << rho_input_bits_old_padded_2[i] ;
    std::cout << std::endl;

    std:: cout << "eol_old_2: ";
    for (size_t i{0}; i < digest_len; i++)
        std:: cout  << eol_old_2[i] ;
    std::cout << std::endl;
}

// #endif