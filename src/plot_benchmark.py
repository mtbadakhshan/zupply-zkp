import subprocess
import json
import matplotlib.pyplot as plt
import os
import csv

def circuit_name(circuit_id):
    if circuit_id == 0:   return "Auth"
    elif circuit_id == 1: return "Trans"
    elif circuit_id == 2: return "Merge"
    elif circuit_id == 3: return "Div"
    else: raise Exception("Invalid Circuit ID.")

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


def plot_write_benchmark_results(results, csv_directory_name):
    plt.figure(figsize=(10, 6))
    fig, ax1 = plt.subplots()
    ax2 = ax1.twinx()

    markers = ['o', '^', 'v', '<', '>', 'x', 'p', '*', 's', 'D']

    for circuit in range(0,4):
        print("cicuit:", circuit)
        for i, (algo, aggregate_name ) in enumerate(results[circuit].items()):
            marker = markers[i % len(markers)]
            if (algo[0:2] =="BM"):
                print(algo+str(circuit))
                ax1.plot(aggregate_name['mean']['range'], aggregate_name['mean']['value'], label=algo+"_"+circuit_name(circuit), marker=marker, markersize=3, linewidth=1)
            else:
                ax2.plot(aggregate_name['mean']['range'], aggregate_name['mean']['value'], label=algo+"_"+circuit_name(circuit), marker=marker, markersize=3, linewidth=1)

            csv_file_name= csv_directory_name + algo+"_"+circuit_name(circuit)+".csv"
            with open(csv_file_name, mode='w', newline='') as csv_file:
                writer = csv.writer(csv_file)
                if (algo[0:2] =="BM"):
                    writer.writerow(['Range', 'Mean CPU Time (microseconds)'])
                else:
                    writer.writerow(['Range', 'bytes'])

                for r, mean in zip(aggregate_name['mean']['range'], aggregate_name['mean']['value']):
                    writer.writerow([r, mean])
            
            print(f"Data for {algo+"_"+circuit_name(circuit)} written to {csv_file_name}")
                
            
    
    ax1.set_xlabel('L (# Merkle hash tree layers)')
    ax1.set_ylabel('Time (microseconds)')
    ax2.set_ylabel('bytes')
    # plt.yscale('log')
    plt.title('Benchmark Comparison of Additive FFT Algorithms (Logarithmic Scale)')
    plt.legend()
    plt.grid(True, which="both", ls="--")
    plt.show()


# Main script execution
if __name__ == "__main__":
    root_path = "../benchmark_data/BN128/"
    output_file = root_path + "benchmark_output.json"
    csv_directory_name = root_path + "csv_files/"
    min_tree_depth = 17
    max_tree_depth = 20
    benchmark_repetitions = 1

    try:
        os.mkdir(csv_directory_name)
        print(f"Directory '{csv_directory_name}' created successfully.")
    except FileExistsError:
        print(f"Directory '{csv_directory_name}' already exists.")
    except PermissionError:
        print(f"Permission denied: Unable to create '{csv_directory_name}'.")
    except Exception as e:
        print(f"An error occurred: {e}")
    
    # Run the benchmark if the output file does not exist
    if not os.path.exists(output_file):
        run_benchmark(min_tree_depth, max_tree_depth, benchmark_repetitions, output_file)
    
    # Parse the benchmark output
    benchmark_results = parse_benchmark_output(output_file)

    # print(json.dumps(benchmark_results, indent=4))
    # print(benchmark_results[0].items())
    
    # Plot the results
    plot_write_benchmark_results(benchmark_results, csv_directory_name)