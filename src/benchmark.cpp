#include <benchmark/benchmark.h>
#include <cstdlib>
#include <chrono>

#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/algebra/curves/bn128/bn128_init.hpp>
#include <libff/algebra/curves/bn128/bn128_g1.hpp>
#include <libff/algebra/curves/bn128/bn_utils.hpp>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"

#include "libiop/algebra/utils.hpp"
#include "libiop/relations/r1cs.hpp"
#include <libiop/snark/aurora_snark.hpp>
#include <libiop/protocols/ldt/ldt_reducer.hpp>
#include <stdexcept>


#include "np_circuits/circuit.hpp"
#include "utils.hpp"


typedef libff::Fr<libff::bn128_pp> FieldT;
typedef libsnark::sha256_two_to_one_hash_gadget<FieldT> HashT;
typedef libff::bn128_pp ppT;
typedef libiop::binary_hash_digest hash_type;

// Benchmark for Libsnark Prover -----------------------------------------------------------------------------------------------------------------------
static void BM_PROVER_LIBSNARK(benchmark::State &state)
{
    const size_t tree_depth = state.range(0);
    const size_t circuit_selector = state.range(1);

    libff::start_profiling();
    libff::bn128_pp::init_public_params();
    std::srand ( std::time(NULL) );

    std::unique_ptr<Circuit<FieldT, HashT, ppT>> circuit = selectCircuit<FieldT, HashT, ppT>(circuit_selector, tree_depth);
    r1cs_constraint_system<FieldT> libsnark_r1cs = circuit->get_r1cs_constraints();
    r1cs_gg_ppzksnark_proof<ppT> libsnark_proof;

    for (auto _ : state)
    {   
        benchmark::DoNotOptimize(circuit);
        benchmark::DoNotOptimize(libsnark_proof = r1cs_gg_ppzksnark_prover<ppT>(circuit->get_keypair().pk, circuit->get_primary_input(), circuit->get_auxiliary_input()));
        state.counters["ProofSize (bits)"] = libsnark_proof.size_in_bits();
        state.counters["num_constraints"] = circuit->get_r1cs_constraints().num_constraints();

        benchmark::ClobberMemory();
        
    }
    state.SetItemsProcessed(state.iterations());
}

// Benchmark for Libsnark Verifier -----------------------------------------------------------------------------------------------------------------------
static void BM_VERIFIER_LIBSNARK(benchmark::State &state)
{
    const size_t tree_depth = state.range(0);
    const size_t circuit_selector = state.range(1);

    libff::start_profiling();
    libff::bn128_pp::init_public_params();

    std::srand ( std::time(NULL) );

    std::unique_ptr<Circuit<FieldT, HashT, ppT>> circuit = selectCircuit<FieldT, HashT, ppT>(circuit_selector, tree_depth);
    r1cs_gg_ppzksnark_proof<ppT> libsnark_proof = r1cs_gg_ppzksnark_prover<ppT>(circuit->get_keypair().pk, circuit->get_primary_input(), circuit->get_auxiliary_input());
    bool libsnark_verified;

    for (auto _ : state)
    {   
        benchmark::DoNotOptimize(circuit);
        benchmark::DoNotOptimize(libsnark_proof);
        benchmark::DoNotOptimize(libsnark_verified = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(circuit->get_keypair().vk, circuit->get_primary_input(), libsnark_proof));
        state.counters["PrimaryInputSize (bits)"] = circuit->get_primary_input().size() * FieldT::num_bits;
        benchmark::ClobberMemory();
        
    }
    state.SetItemsProcessed(state.iterations());
}

// Benchmark for Libiop Prover -----------------------------------------------------------------------------------------------------------------------
static void BM_PROVER_LIBIOP(benchmark::State &state)
{
    const size_t tree_depth = state.range(0);
    const size_t circuit_selector = state.range(1);

    libff::start_profiling();
    libff::bn128_pp::init_public_params();
    std::srand ( std::time(NULL) );

    std::unique_ptr<Circuit<FieldT, HashT, ppT>> circuit = selectCircuit<FieldT, HashT, ppT>(circuit_selector, tree_depth);
    libiop::r1cs_primary_input<FieldT> primary_input = circuit->get_primary_input();
	libiop::r1cs_auxiliary_input<FieldT> auxiliary_input = circuit->get_auxiliary_input();
    libiop::r1cs_constraint_system<FieldT> libiop_r1cs = convert_libsnark_to_libiop<FieldT>(circuit->get_r1cs_constraints(), primary_input, auxiliary_input);
    libiop::aurora_snark_parameters<FieldT, hash_type> params = generate_aurora_parameters<FieldT, hash_type>(libiop_r1cs);

    libiop::aurora_snark_argument<FieldT, hash_type> libiop_proof;
    bool libsnark_verified;

    for (auto _ : state)
    {   
        benchmark::DoNotOptimize(libiop_r1cs);
        benchmark::DoNotOptimize(auxiliary_input);
        benchmark::DoNotOptimize(libiop_proof = libiop::aurora_snark_prover<FieldT>(  libiop_r1cs, primary_input, auxiliary_input, params));
        state.counters["ProofSize (bytes)"] = libiop_proof.size_in_bytes();
        state.counters["num_constraints"] = libiop_r1cs.num_constraints();

        benchmark::ClobberMemory();
        
    }
    state.SetItemsProcessed(state.iterations());
}


// Benchmark for Libiop Verifier -----------------------------------------------------------------------------------------------------------------------
static void BM_VERIFIER_LIBIOP(benchmark::State &state)
{
    const size_t tree_depth = state.range(0);
    const size_t circuit_selector = state.range(1);

    libff::start_profiling();
    libff::bn128_pp::init_public_params();
    std::srand ( std::time(NULL) );

    std::unique_ptr<Circuit<FieldT, HashT, ppT>> circuit = selectCircuit<FieldT, HashT, ppT>(circuit_selector, tree_depth);
    libiop::r1cs_primary_input<FieldT> primary_input = circuit->get_primary_input();
	libiop::r1cs_auxiliary_input<FieldT> auxiliary_input = circuit->get_auxiliary_input();
    libiop::r1cs_constraint_system<FieldT> libiop_r1cs = convert_libsnark_to_libiop<FieldT>(circuit->get_r1cs_constraints(), primary_input, auxiliary_input);
    libiop::aurora_snark_parameters<FieldT, hash_type> params = generate_aurora_parameters<FieldT, hash_type>(libiop_r1cs);

    libiop::aurora_snark_argument<FieldT, hash_type> libiop_proof = libiop::aurora_snark_prover<FieldT>(  libiop_r1cs, primary_input, auxiliary_input, params);
    bool libsnark_verified;

    for (auto _ : state)
    {   
        benchmark::DoNotOptimize(libiop_r1cs);
        benchmark::DoNotOptimize(libiop_proof);
        benchmark::DoNotOptimize(libsnark_verified = libiop::aurora_snark_verifier<FieldT>( libiop_r1cs, primary_input, libiop_proof, params));
        state.counters["ProofSize (bytes)"] = libiop_proof.size_in_bytes();
        benchmark::ClobberMemory();
        
    }
    state.SetItemsProcessed(state.iterations());
}

const int MIN_RANGE = std::stoi(std::getenv("BM_MIN_RANGE"));
const int MAX_RANGE = std::stoi(std::getenv("BM_MAX_RANGE"));

BENCHMARK(BM_PROVER_LIBSNARK)->ArgsProduct({benchmark::CreateDenseRange(MIN_RANGE, MAX_RANGE, 1), {Select_AuthCircuit, Select_TransCircuit, Select_MergeCircuit, Select_DivCircuit}})->Unit(benchmark::kMicrosecond)->ReportAggregatesOnly(true);
BENCHMARK(BM_VERIFIER_LIBSNARK)->ArgsProduct({benchmark::CreateDenseRange(MIN_RANGE, MAX_RANGE, 1), {Select_AuthCircuit, Select_TransCircuit, Select_MergeCircuit, Select_DivCircuit}})->Unit(benchmark::kMicrosecond)->ReportAggregatesOnly(true);
BENCHMARK(BM_PROVER_LIBIOP)->ArgsProduct({benchmark::CreateDenseRange(MIN_RANGE, MAX_RANGE, 1), {Select_AuthCircuit, Select_TransCircuit, Select_MergeCircuit, Select_DivCircuit}})->Unit(benchmark::kMicrosecond)->ReportAggregatesOnly(true);
BENCHMARK(BM_VERIFIER_LIBIOP)->ArgsProduct({benchmark::CreateDenseRange(MIN_RANGE, MAX_RANGE, 1), {Select_AuthCircuit, Select_TransCircuit, Select_MergeCircuit, Select_DivCircuit}})->Unit(benchmark::kMicrosecond)->ReportAggregatesOnly(true);


BENCHMARK_MAIN();