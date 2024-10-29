/** @file
 *****************************************************************************
 * @author     This file is part of Zupply, developed by Mohammadtaghi Badakhshan
 *
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <cstddef>
#ifndef CIRCUIT_HPP
#error "utils.tcc should not be included directly. Include utils.hpp instead."
#endif

#include "circuit.hpp"


/* ====================================================================================================================== */
/* -------- DivCircuit ------------------------------------------------------------------------------------------------ */
/* ====================================================================================================================== */
template <typename FieldT, typename HashT, typename ppT>
DivCircuit<FieldT, HashT, ppT>::DivCircuit(const std::string &name, const size_t tree_depth) : Circuit<FieldT, HashT, ppT>(name, tree_depth)
{

    std::cout << "/* --- DivCircuit --- */" << std::endl;

    const size_t q_len = 64;
    const size_t PKsig_len = 256;
    const size_t rho_len = 192;

    // public inputs
    libff::bit_vector root(HashT::get_digest_len());
    libff::bit_vector cm_new_1(HashT::get_digest_len());
    libff::bit_vector cm_new_2(HashT::get_digest_len());
    libff::bit_vector eol_old(HashT::get_digest_len());

    // private inputs
    libff::bit_vector q_input_bits_old(q_len);
    libff::bit_vector PKsig_input_bits_old(PKsig_len);
    libff::bit_vector rho_input_bits_old(rho_len);

    libff::bit_vector q_input_bits_new_1(q_len);
    libff::bit_vector PKsig_input_bits_new_1(PKsig_len);
    libff::bit_vector rho_input_bits_new_1(rho_len);

    libff::bit_vector q_input_bits_new_2(q_len);
    libff::bit_vector PKsig_input_bits_new_2(PKsig_len);
    libff::bit_vector rho_input_bits_new_2(rho_len);


    libff::bit_vector address_bits;
    size_t address;
    std::vector<merkle_authentication_node> path(tree_depth);


    generate_random_inputs(root, cm_new_1, cm_new_2, eol_old, q_input_bits_old, PKsig_input_bits_old, rho_input_bits_old, q_input_bits_new_1,
                           PKsig_input_bits_new_1, rho_input_bits_new_1, q_input_bits_new_2, PKsig_input_bits_new_2, rho_input_bits_new_2, 
                           address_bits, address, path);

    setup(root, cm_new_1, cm_new_2, eol_old, q_input_bits_old, PKsig_input_bits_old, rho_input_bits_old, q_input_bits_new_1,
            PKsig_input_bits_new_1, rho_input_bits_new_1, q_input_bits_new_2, PKsig_input_bits_new_2, rho_input_bits_new_2, 
            address_bits, address, path);
}

/* --- SETUP --- */
template <typename FieldT, typename HashT, typename ppT>
void DivCircuit<FieldT, HashT, ppT>::setup(libff::bit_vector root,
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

    // /* Public Inputs */
    
    // root
    pb_variable<FieldT> root_128bit_1;
    pb_variable<FieldT> root_128bit_2;
    root_128bit_1.allocate(pb, "root_128bit_part1");
    root_128bit_2.allocate(pb, "root_128bit_part2");

    // cm_new_1
    pb_variable<FieldT> cm_new_1_128bit_1;
    pb_variable<FieldT> cm_new_1_128bit_2;
    cm_new_1_128bit_1.allocate(pb, "cm_new_1_128bit_part1");
    cm_new_1_128bit_2.allocate(pb, "cm_new_1_128bit_part2");

    // cm_new_2
    pb_variable<FieldT> cm_new_2_128bit_1;
    pb_variable<FieldT> cm_new_2_128bit_2;
    cm_new_2_128bit_1.allocate(pb, "cm_new_2_128bit_part1");
    cm_new_2_128bit_2.allocate(pb, "cm_new_2_128bit_part2");

    // eol_old
    pb_variable<FieldT> eol_old_128bit_1;
    pb_variable<FieldT> eol_old_128bit_2;
    eol_old_128bit_1.allocate(pb, "eol_old_128bit_part1");
    eol_old_128bit_2.allocate(pb, "eol_old_128bit_part2");

    /* Connecting Public inputs */
    digest_variable<FieldT> root_digest(pb, digest_len, "root_digest");
    digest_variable<FieldT> cm_new_1_digest(pb, digest_len, "cm_new_1_digest");
    digest_variable<FieldT> cm_new_2_digest(pb, digest_len, "cm_new_2_digest");
    digest_variable<FieldT> eol_old_digest(pb, digest_len, "eol_old_digest");

    linear_combination<FieldT> root_128bit_lc_1, root_128bit_lc_2;
    linear_combination<FieldT> cm_new_1_128bit_lc_1, cm_new_1_128bit_lc_2;
    linear_combination<FieldT> cm_new_2_128bit_lc_1, cm_new_2_128bit_lc_2;
    linear_combination<FieldT> eol_old_128bit_lc_1, eol_old_128bit_lc_2;

    for (size_t i = 0; i < 128; ++i)
    {
        root_128bit_lc_1.add_term(root_digest.bits[i], libff::power<FieldT>(2, i));
        root_128bit_lc_2.add_term(root_digest.bits[i + 128], libff::power<FieldT>(2, i));

        cm_new_1_128bit_lc_1.add_term(cm_new_1_digest.bits[i], libff::power<FieldT>(2, i));
        cm_new_1_128bit_lc_2.add_term(cm_new_1_digest.bits[i + 128], libff::power<FieldT>(2, i));

        cm_new_2_128bit_lc_1.add_term(cm_new_2_digest.bits[i], libff::power<FieldT>(2, i));
        cm_new_2_128bit_lc_2.add_term(cm_new_2_digest.bits[i + 128], libff::power<FieldT>(2, i));

        eol_old_128bit_lc_1.add_term(eol_old_digest.bits[i], libff::power<FieldT>(2, i));
        eol_old_128bit_lc_2.add_term(eol_old_digest.bits[i + 128], libff::power<FieldT>(2, i));
    }

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(root_128bit_lc_1, FieldT::one(), root_128bit_1), "Root part 1 Constraints");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(root_128bit_lc_2, FieldT::one(), root_128bit_2), "Root part 2 Constraints");

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(cm_new_1_128bit_lc_1, FieldT::one(), cm_new_1_128bit_1), "cm_new_1 part 1 Constraints");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(cm_new_1_128bit_lc_2, FieldT::one(), cm_new_1_128bit_2), "cm_new_1 part 2 Constraints");

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(cm_new_2_128bit_lc_1, FieldT::one(), cm_new_2_128bit_1), "cm_new_2 part 1 Constraints");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(cm_new_2_128bit_lc_2, FieldT::one(), cm_new_2_128bit_2), "cm_new_2 part 2 Constraints");

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

    // new cm_1 inputs
    pb_variable_array<FieldT> q_input_new_1;
    q_input_new_1.allocate(pb, q_len, "q_input_new_1");
    // ---
    pb_variable_array<FieldT> PKsig_input_new_1;
    PKsig_input_new_1.allocate(pb, PKsig_len, "PKsig_input_new_1");
    // ---
    pb_variable_array<FieldT> rho_input_new_1;
    rho_input_new_1.allocate(pb, rho_len, "rho_input_new_1");

    std::vector<pb_variable_array<FieldT>> input_new_parts_1;
    input_new_parts_1.push_back(q_input_new_1);
    input_new_parts_1.push_back(PKsig_input_new_1);
    input_new_parts_1.push_back(rho_input_new_1);

    // new cm_2 inputs
    pb_variable_array<FieldT> q_input_new_2;
    q_input_new_2.allocate(pb, q_len, "q_input_new_2");
    // ---
    pb_variable_array<FieldT> PKsig_input_new_2;
    PKsig_input_new_2.allocate(pb, PKsig_len, "PKsig_input_new_2");
    // ---
    pb_variable_array<FieldT> rho_input_new_2;
    rho_input_new_2.allocate(pb, rho_len, "rho_input_new_2");

    std::vector<pb_variable_array<FieldT>> input_new_parts_2;
    input_new_parts_2.push_back(q_input_new_2);
    input_new_parts_2.push_back(PKsig_input_new_2);
    input_new_parts_2.push_back(rho_input_new_2);


    pb_variable_array<FieldT> zero_padding_rho;
    zero_padding_rho.allocate(pb, SHA256_block_size - rho_len, "zero_padding_rho");

    std::vector<pb_variable_array<FieldT>> input_for_eol_crh_parts;
    input_for_eol_crh_parts.push_back(zero_padding_rho);
    input_for_eol_crh_parts.push_back(rho_input_old);


    block_variable<FieldT> input_old(pb, input_old_parts, "input_old");                                     // It's "q", "PK_sig", "rho"
    block_variable<FieldT> input_new_1(pb, input_new_parts_1, "input_new_1");                               // It's "q", "PK_sig", "rho"
    block_variable<FieldT> input_new_2(pb, input_new_parts_2, "input_new_2");                               // It's "q", "PK_sig", "rho"
    block_variable<FieldT> input_for_eol_crh(pb, input_for_eol_crh_parts, "input_for_eol_crh");       // It's "0000...0000", "rho"

    // /* Building the comparator */
    // // q_input_new_1 + q_input_new_2 == q_input_old
    is_sum_equal_gadget<FieldT> sum_comparator(pb, q_input_new_1, q_input_new_2, q_input_old, "comparator");

    /* Building the MHT */
    pb_variable_array<FieldT> address_bits_va;
    address_bits_va.allocate(pb, tree_depth, "address_bits_va");
    digest_variable<FieldT> leaf_digest(pb, digest_len, "leaf_digest");
    merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
    merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

    // /* Building CRH to get commitment  old cm */
    sha256_two_to_one_hash_gadget<FieldT> crh_old(pb, SHA256_block_size, input_old, leaf_digest, "crh_old");
    sha256_two_to_one_hash_gadget<FieldT> crh_new_1(pb, SHA256_block_size, input_new_1, cm_new_1_digest, "crh_new_1");
    sha256_two_to_one_hash_gadget<FieldT> crh_new_2(pb, SHA256_block_size, input_new_2, cm_new_2_digest, "crh_new_2");
    sha256_two_to_one_hash_gadget<FieldT> crh_eol(pb, SHA256_block_size, input_for_eol_crh, eol_old_digest, "crh_eol_old");

    /* Setting the public input*/
    // The first 4*256 bits assigned to the protoboard which are root_digest, cm_new_digest, eol_old_1_digest, and eol_old_2_digest
    // These are determined as public inputs */
    pb.set_input_sizes(2 * 4);

    std::cout << "/* --- Trusted Setup : Generating the CRS (keypar) --- */" << std::endl;
    /* Trusted Setup : Generating the CRS (keypar) */

    sum_comparator.generate_r1cs_constraints();
    crh_old.generate_r1cs_constraints();
    crh_new_1.generate_r1cs_constraints();
    crh_new_2.generate_r1cs_constraints();
    crh_eol.generate_r1cs_constraints();
    path_var.generate_r1cs_constraints();
    ml.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(constraint_system);

    // // Warning: check that the assignment operation is implemented correctly - avoid shallow copy
    this->keypair.pk = keypair.pk;
    this->keypair.vk = keypair.vk;
    this->r1cs_constraints = constraint_system;

    const size_t num_constraints = pb.num_constraints();
    const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth) + sha256_two_to_one_hash_gadget<FieldT>::expected_constraints(SHA256_block_size) * 4 + 8 + 1; // for the comparison
    assert(num_constraints == expected_constraints);

    if (num_constraints != expected_constraints)
    {
        std::cerr << "num_constraints:" << num_constraints << ",  expected_constraints:" << expected_constraints << std::endl;
        return;
    }

    std::cout << "Setup done - num_constraints:" << num_constraints << std::endl;

    std::cout << "/* --- Witness Generation --- */" << std::endl;

    /* Witness Generation according to the function's input parameters */

    q_input_old.fill_with_bits(pb, q_input_bits_old);
    PKsig_input_old.fill_with_bits(pb, PKsig_input_bits_old);
    rho_input_old.fill_with_bits(pb, rho_input_bits_old);

    q_input_new_1.fill_with_bits(pb, q_input_bits_new_1);
    PKsig_input_new_1.fill_with_bits(pb, PKsig_input_bits_new_1);
    rho_input_new_1.fill_with_bits(pb, rho_input_bits_new_1);
    
    q_input_new_2.fill_with_bits(pb, q_input_bits_new_2);
    PKsig_input_new_2.fill_with_bits(pb, PKsig_input_bits_new_2);
    rho_input_new_2.fill_with_bits(pb, rho_input_bits_new_2);

    libff::bit_vector input_bits_old(q_input_bits_old);
    input_bits_old.insert(input_bits_old.end(), PKsig_input_bits_old.begin(), PKsig_input_bits_old.end());
    input_bits_old.insert(input_bits_old.end(), rho_input_bits_old.begin(), rho_input_bits_old.end());


    libff::bit_vector input_bits_new_1(q_input_bits_new_1);
    input_bits_new_1.insert(input_bits_new_1.end(), PKsig_input_bits_new_1.begin(), PKsig_input_bits_new_1.end());
    input_bits_new_1.insert(input_bits_new_1.end(), rho_input_bits_new_1.begin(), rho_input_bits_new_1.end());


    libff::bit_vector input_bits_new_2(q_input_bits_new_2);
    input_bits_new_2.insert(input_bits_new_2.end(), PKsig_input_bits_new_2.begin(), PKsig_input_bits_new_2.end());
    input_bits_new_2.insert(input_bits_new_2.end(), rho_input_bits_new_2.begin(), rho_input_bits_new_2.end());

    libff::bit_vector zero_padding_rho_bits(SHA256_block_size - rho_len, 0);

    libff::bit_vector input_for_eol_crh_bits(zero_padding_rho_bits);
    input_for_eol_crh_bits.insert(input_for_eol_crh_bits.end(), rho_input_bits_old.begin(), rho_input_bits_old.end());

    // libff::bit_vector input_for_eol_crh_bits_2(zero_padding_rho_bits);
    // input_for_eol_crh_bits_2.insert(input_for_eol_crh_bits_2.end(), rho_input_bits_old_2.begin(), rho_input_bits_old_2.end());

    libff::bit_vector leaf_cm_old_bits = HashT::get_hash(input_bits_old);
    // libff::bit_vector leaf_cm_old_bits_2 = HashT::get_hash(input_bits_old_2);

    for (size_t i = 0; i < 128; ++i)
    {
        pb.val(root_128bit_1) += root[i] ? libff::power<FieldT>(2, i) : 0;
        pb.val(root_128bit_2) += root[i + 128] ? libff::power<FieldT>(2, i) : 0;

        pb.val(cm_new_1_128bit_1) += cm_new_1[i] ? libff::power<FieldT>(2, i) : 0;
        pb.val(cm_new_1_128bit_2) += cm_new_1[i + 128] ? libff::power<FieldT>(2, i) : 0;

        pb.val(cm_new_2_128bit_1) += cm_new_2[i] ? libff::power<FieldT>(2, i) : 0;
        pb.val(cm_new_2_128bit_2) += cm_new_2[i + 128] ? libff::power<FieldT>(2, i) : 0;

        pb.val(eol_old_128bit_1) += eol_old[i] ? libff::power<FieldT>(2, i) : 0;
        pb.val(eol_old_128bit_2) += eol_old[i + 128] ? libff::power<FieldT>(2, i) : 0;

   }


    if (HashT::get_hash(input_bits_new_1) == cm_new_1){
        std::cout << "Passed! on cm_new_1" << std::endl;
    } else {
        std::cout << " Error! on cm_new_1" << std::endl;
    }

    if (HashT::get_hash(input_bits_new_2) == cm_new_2){
        std::cout << "Passed! on cm_new_2" << std::endl;
    } else {
        std::cout << " Error! on cm_new_2" << std::endl;
    }

    if (HashT::get_hash(input_for_eol_crh_bits) == eol_old){
        std::cout << "Passed! on eol_old" << std::endl;
    }

    root_digest.generate_r1cs_witness(root);
    cm_new_1_digest.generate_r1cs_witness(cm_new_1);
    cm_new_2_digest.generate_r1cs_witness(cm_new_2);
    eol_old_digest.generate_r1cs_witness(eol_old);

    address_bits_va.fill_with_bits(pb, address_bits);
    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);

    leaf_digest.generate_r1cs_witness(leaf_cm_old_bits);
    input_old.generate_r1cs_witness(input_bits_old);

    input_new_1.generate_r1cs_witness(input_bits_new_1);
    input_new_2.generate_r1cs_witness(input_bits_new_2);
    input_for_eol_crh.generate_r1cs_witness(input_for_eol_crh_bits);

    path_var.generate_r1cs_witness(address, path);

    ml.generate_r1cs_witness();
    crh_old.generate_r1cs_witness();
    crh_new_1.generate_r1cs_witness();
    crh_new_2.generate_r1cs_witness();
    crh_eol.generate_r1cs_witness();

    libff::bit_vector computed_root = ml.root.bits.get_bits(pb);
    if (computed_root != root){
        std::cout << "Error! ml" << std::endl;
        std:: cout << "computed_root: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << computed_root[i] ;
        std::cout << std::endl;

        std:: cout << "root: ";
        for (size_t i{0}; i < digest_len; i++)
            std:: cout  << root[i] ;
        std::cout << std::endl;
    }



    // // /* make sure that read checker didn't accidentally overwrite anything */
    address_bits_va.fill_with_bits(pb, address_bits);

    if (address_bits_va.get_field_element_from_bits(pb).as_ulong() != address){
        std::cout << "address_bits_va_1.get_field_element_from_bits(pb).as_ulong() != address_1";
    }

    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);

    leaf_digest.generate_r1cs_witness(leaf_cm_old_bits);

    input_old.generate_r1cs_witness(input_bits_old);

    input_new_1.generate_r1cs_witness(input_bits_new_1);
    input_new_2.generate_r1cs_witness(input_bits_new_2);
    input_for_eol_crh.generate_r1cs_witness(input_for_eol_crh_bits);

    path_var.generate_r1cs_witness(address, path);

    root_digest.generate_r1cs_witness(root);
    cm_new_1_digest.generate_r1cs_witness(cm_new_1);
    cm_new_2_digest.generate_r1cs_witness(cm_new_2);
    eol_old_digest.generate_r1cs_witness(eol_old);


    assert(pb.is_satisfied());

    if (!pb.is_satisfied())
    {
        std::cerr << "pb is Not Satisfied" << std::endl;
        return;
    }
    std::cout << "pb is satisfied!" << std::endl;


    this->primary_input = pb.primary_input();
    std::cout << "Primary inputes are assigned!" << std::endl;

    this->auxiliary_input = pb.auxiliary_input();
    std::cout << "Auxiliary inputes are assigned!" << std::endl;

}

/* --- GENERATE RANDOM INPUTS --- */
template <typename FieldT, typename HashT, typename ppT>
void DivCircuit<FieldT, HashT, ppT>::generate_random_inputs( libff::bit_vector &root,
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
    std::vector<merkle_authentication_node> &path)
{
    std::cout << "/* --- GENERATE RANDOM INPUTS --- */" << std::endl;
    /* Generating random input */
    // In actual implementation it should be generated secretly and passed by the user.
    const size_t digest_len = HashT::get_digest_len();
    const size_t q_len = 64;
    const size_t rho_len = 192;
    const size_t tree_depth = this->tree_depth;


    q_input_bits_new_1[0] = 0; // the offset is to prevent overflow
    std::generate(q_input_bits_new_1.begin() + 1, q_input_bits_new_1.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(PKsig_input_bits_new_1.begin(), PKsig_input_bits_new_1.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(rho_input_bits_new_1.begin(), rho_input_bits_new_1.end(), [&]()
                  { return std::rand() % 2; });

    q_input_bits_new_2[0] = 0; // the offset is to prevent overflow
    std::generate(q_input_bits_new_2.begin() + 1, q_input_bits_new_2.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(PKsig_input_bits_new_2.begin(), PKsig_input_bits_new_2.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(rho_input_bits_new_2.begin(), rho_input_bits_new_2.end(), [&]()
                  { return std::rand() % 2; });

    std::generate(PKsig_input_bits_old.begin(), PKsig_input_bits_old.end(), [&]()
                  { return std::rand() % 2; });
    std::generate(rho_input_bits_old.begin(), rho_input_bits_old.end(), [&]()
                  { return std::rand() % 2; });

    // Full Adder : q_input_bits_old = q_input_bits_new_1 + q_input_bits_new_2
    bool carry_bit = 0;
    for (size_t i = q_len - 1; i > 0; i--)
    {
        q_input_bits_old[i] = (q_input_bits_new_1[i] ^ q_input_bits_new_2[i]) ^ carry_bit;
        carry_bit = ((q_input_bits_new_1[i] ^ q_input_bits_new_2[i]) & carry_bit) | (q_input_bits_new_1[i] & q_input_bits_new_2[i]);
    }
    q_input_bits_old[0] = carry_bit;

    std:: cout << "q_input_bits_new_1: ";
    for (size_t i{0}; i < q_len; i++)
        std:: cout  << q_input_bits_new_1[i] ;
    std::cout << std::endl;

    std:: cout << "q_input_bits_new_2: ";
    for (size_t i{0}; i < q_len; i++)
        std:: cout  << q_input_bits_new_2[i] ;
    std::cout << std::endl;

    std:: cout << "q_input_bits_old: ";
    for (size_t i{0}; i < q_len; i++)
        std:: cout  << q_input_bits_old[i] ;
    std::cout << std::endl;


    libff::bit_vector input_bits_new_1(q_input_bits_new_1);
    input_bits_new_1.insert(input_bits_new_1.end(), PKsig_input_bits_new_1.begin(), PKsig_input_bits_new_1.end());
    input_bits_new_1.insert(input_bits_new_1.end(), rho_input_bits_new_1.begin(), rho_input_bits_new_1.end());

    libff::bit_vector input_bits_new_2(q_input_bits_new_2);
    input_bits_new_2.insert(input_bits_new_2.end(), PKsig_input_bits_new_2.begin(), PKsig_input_bits_new_2.end());
    input_bits_new_2.insert(input_bits_new_2.end(), rho_input_bits_new_2.begin(), rho_input_bits_new_2.end());

    libff::bit_vector input_bits_old(q_input_bits_old);
    input_bits_old.insert(input_bits_old.end(), PKsig_input_bits_old.begin(), PKsig_input_bits_old.end());
    input_bits_old.insert(input_bits_old.end(), rho_input_bits_old.begin(), rho_input_bits_old.end());

    // Generating the Merkle tree
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

    cm_new_1 = HashT::get_hash(input_bits_new_1);
    cm_new_2 = HashT::get_hash(input_bits_new_2);

    libff::bit_vector zero_padding_rho_bits(SHA256_block_size - rho_len, 0);
    libff::bit_vector rho_input_bits_old_padded(zero_padding_rho_bits);
    rho_input_bits_old_padded.insert(rho_input_bits_old_padded.end(), rho_input_bits_old.begin(), rho_input_bits_old.end());
    eol_old = HashT::get_hash(rho_input_bits_old_padded);
}
