/** @file
 *****************************************************************************
 * @author     This file is part of Zupply, developed by Mohammadtaghi Badakhshan
 *      
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <iostream>
#include <fstream>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
#include <libiop/bcs/bcs_common.hpp>

#include <libiop/relations/r1cs.hpp>

#include "np_circuits/circuit.hpp" // Include the header where Circuit is defined

using namespace libsnark;

template<typename FieldT, typename HashT, typename ppT>
void save_pp(Circuit<FieldT, HashT, ppT> circuit, const std::string path);

template<typename FieldT, typename HashT, typename ppT>
void save_proof(r1cs_gg_ppzksnark_proof<ppT> proof, r1cs_primary_input<FieldT> primary_input, const std::string path);

template<typename FieldT>
libiop::r1cs_constraint_system<FieldT> convert_libsnark_to_libiop(r1cs_constraint_system<FieldT> libsnart_r1cs);


template<typename FieldT, typename hash_type>
void save_proof(libiop::aurora_snark_argument<FieldT, hash_type> proof, r1cs_primary_input<FieldT> primary_input, const std::string path);



#include "utils.tcc" // Include the implementation

#endif // UTILS_HPP