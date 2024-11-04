import subprocess
import json
import matplotlib.pyplot as plt
import os

# Build and run the benchmark (assuming the build directory is './build' and cmake is configured)
def run_benchmark(min_range, max_range, benchmark_repetitions, output_file="benchmark_output.json"):
    os.environ['BM_MIN_RANGE'] = str(min_range)
    os.environ['BM_MAX_RANGE'] = str(max_range)
    # Command to run the benchmark and output results to JSON format
    benchmark_command = [
        "../build/src/run_benchmark",  # Replace with your actual executable name
        f"--benchmark_repetitions={benchmark_repetitions}",
        f"--benchmark_out={output_file}"
    ]
    
    # Running the benchmark
    subprocess.run(benchmark_command, check=True)
    print(f"Benchmark results saved to {output_file}")

def parse_benchmark_output(output_file="benchmark_output.json"):
    with open(output_file, 'r') as f:
        data = json.load(f)
    
    results = {}
    
    for benchmark in data['benchmarks']:
        # if (benchmark['aggregate_name'] == 'mean'):
        algo_name = benchmark['run_name'].split('/')[0]
        range_val = int(benchmark['run_name'].split('/')[1])
        circuit = int(benchmark['run_name'].split('/')[2])

        # print("circuit: ", circuit)
        
        if circuit not in results:
            results[circuit] = {}
            results[circuit]["LIBSNARK-Proof_size"] = {}
            results[circuit]["LIBIOP-Proof_size"] = {}
            results[circuit]["LIBSNARK-num_constraints"] = {}
            results[circuit]["LIBIOP-num_constraints"] = {}
        
        if algo_name not in results[circuit]:
            results[circuit][algo_name] = {}

        if benchmark['aggregate_name'] not in results[circuit][algo_name]:
            results[circuit][algo_name][benchmark['aggregate_name']] = {'range': [], 'value': []}

        if benchmark['aggregate_name'] not in results[circuit]["LIBSNARK-Proof_size"]:
            results[circuit]["LIBSNARK-Proof_size"][benchmark['aggregate_name']] = {'range': [], 'value': []}

        if benchmark['aggregate_name'] not in results[circuit]["LIBSNARK-num_constraints"]:
            results[circuit]["LIBSNARK-num_constraints"][benchmark['aggregate_name']] = {'range': [], 'value': []}

        if benchmark['aggregate_name'] not in results[circuit]["LIBIOP-Proof_size"]:
            results[circuit]["LIBIOP-Proof_size"][benchmark['aggregate_name']] = {'range': [], 'value': []}

        if benchmark['aggregate_name'] not in results[circuit]["LIBIOP-num_constraints"]:
            results[circuit]["LIBIOP-num_constraints"][benchmark['aggregate_name']] = {'range': [], 'value': []}

        
        results[circuit][algo_name][benchmark['aggregate_name']]['range'].append(range_val)
        results[circuit][algo_name][benchmark['aggregate_name']]['value'].append(benchmark['cpu_time'])  # Convert to microseconds

        if algo_name == "BM_PROVER_LIBSNARK":
            results[circuit]["LIBSNARK-Proof_size"][benchmark['aggregate_name']]['range'].append(range_val)
            results[circuit]["LIBSNARK-Proof_size"][benchmark['aggregate_name']]['value'].append(benchmark['ProofSize (bits)']/8)

            results[circuit]["LIBSNARK-num_constraints"][benchmark['aggregate_name']]['range'].append(range_val)
            results[circuit]["LIBSNARK-num_constraints"][benchmark['aggregate_name']]['value'].append(benchmark['num_constraints'])

        if algo_name == "BM_PROVER_LIBIOP":
            results[circuit]["LIBIOP-Proof_size"][benchmark['aggregate_name']]['range'].append(range_val)
            results[circuit]["LIBIOP-Proof_size"][benchmark['aggregate_name']]['value'].append(benchmark['ProofSize (bytes)'])

            results[circuit]["LIBIOP-num_constraints"][benchmark['aggregate_name']]['range'].append(range_val)
            results[circuit]["LIBIOP-num_constraints"][benchmark['aggregate_name']]['value'].append(benchmark['num_constraints'])

    return results


def plot_benchmark_results(results):
    plt.figure(figsize=(10, 6))
    markers = ['o', '^', 'v', '<', '>', 'x', 'p', '*', 's', 'D']

    for i, (algo, aggregate_name ) in enumerate(results[0].items()):
        marker = markers[i % len(markers)]
        print(algo)
        plt.plot(aggregate_name['mean']['range'], aggregate_name['mean']['value'], label=algo, marker=marker, markersize=3, linewidth=1)
    
    plt.xlabel('Range (log2 size)')
    plt.ylabel('Time (microseconds)')
    # plt.yscale('log')
    plt.title('Benchmark Comparison of Additive FFT Algorithms (Logarithmic Scale)')
    plt.legend()
    plt.grid(True, which="both", ls="--")
    plt.show()


# Main script execution
if __name__ == "__main__":
    output_file = "../build/benchmark_output.json"
    min_tree_depth = 10
    max_tree_depth = 25
    benchmark_repetitions = 10
    # Run the benchmark if the output file does not exist
    if not os.path.exists(output_file):
        run_benchmark(min_tree_depth, max_tree_depth, benchmark_repetitions, output_file)
    
    # Parse the benchmark output
    benchmark_results = parse_benchmark_output(output_file)

    # print(json.dumps(benchmark_results, indent=4))
    # print(benchmark_results[0].items())
    
    # Plot the results
    plot_benchmark_results(benchmark_results)