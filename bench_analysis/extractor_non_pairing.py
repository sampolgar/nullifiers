import json
import pandas as pd
from pathlib import Path
import os
import re

# Define the base directory for Criterion benchmark results
BASE_DIR = Path("target/criterion")

def extract_mean_ms(json_file: Path) -> float:
    """Extract the mean execution time in milliseconds from a Criterion JSON file."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        mean_ns = data['mean']['point_estimate']  # Mean time in nanoseconds
        return mean_ns / 1_000_000  # Convert to milliseconds
    except (FileNotFoundError, KeyError) as e:
        print(f"Error processing {json_file}: {e}")
        return None

def extract_curve_benchmark_data(base_dir: Path) -> pd.DataFrame:
    """Extract VRF benchmark data for all curves from Criterion directories."""
    all_data = []
    
    # Check if base directory exists
    if not base_dir.exists():
        print(f"Error: Base directory {base_dir} does not exist!")
        return pd.DataFrame()
    
    # Process original BLS12-381 benchmarks
    bls12_381_data = extract_bls12_381_benchmarks(base_dir)
    if bls12_381_data:
        all_data.extend(bls12_381_data)
    
    # Process secp256k1 benchmarks
    secp256k1_data = extract_curve_specific_benchmarks(base_dir, "secp256k1")
    if secp256k1_data:
        all_data.extend(secp256k1_data)
    
    # Process ed25519 benchmarks
    ed25519_data = extract_curve_specific_benchmarks(base_dir, "ed25519")
    if ed25519_data:
        all_data.extend(ed25519_data)
    
    if not all_data:
        print("No benchmark data found in the specified directory!")
        return pd.DataFrame()
    
    df = pd.DataFrame(all_data)
    return df.sort_values(["curve", "implementation", "operation"])

def extract_bls12_381_benchmarks(base_dir: Path) -> list:
    """Extract the original BLS12-381 benchmark data."""
    bls12_381_data = []
    
    # VRF implementations for BLS12-381
    vrf_implementations = ['dy', 'dy_pf', 'dy_pf_priv', 'dy_pf_priv_commited_output', 'dy_priv']
    
    for impl in vrf_implementations:
        impl_dir = base_dir / impl
        if not impl_dir.exists() or not impl_dir.is_dir():
            continue
        
        # For each operation type (eval_prove, verify, etc.)
        for op_dir in impl_dir.iterdir():
            if not op_dir.is_dir():
                continue
            
            operation = op_dir.name
            
            # Rename the verify operations for dy implementation to avoid confusion
            operation_label = operation
            if impl == 'dy' and operation == 'verify':
                operation_label = 'verify_standard'
            elif impl == 'dy' and operation == 'verify_optimized':
                operation_label = 'verify_optimized'
            
            # Find the estimates.json file
            report_dir = op_dir / "new"
            if report_dir.exists():
                json_file = report_dir / "estimates.json"
                if json_file.exists():
                    mean_ms = extract_mean_ms(json_file)
                    if mean_ms is not None:
                        bls12_381_data.append({
                            "curve": "bls12_381",
                            "implementation": impl,
                            "operation": operation_label,
                            "mean_ms": mean_ms
                        })
    
    return bls12_381_data

def extract_curve_specific_benchmarks(base_dir: Path, curve_name: str) -> list:
    """Extract benchmark data for a specific curve (secp256k1 or ed25519)."""
    curve_data = []
    
    # Look for benchmark directories with the curve name prefix
    curve_pattern = re.compile(f"^{curve_name}_(.+)$")
    
    for bench_dir in base_dir.iterdir():
        if not bench_dir.is_dir():
            continue
        
        match = curve_pattern.match(bench_dir.name)
        if match:
            impl = match.group(1)  # Extract the implementation part
            
            # Process each operation in this implementation
            for op_dir in bench_dir.iterdir():
                if not op_dir.is_dir():
                    continue
                
                operation = op_dir.name
                
                # Find the estimates.json file
                report_dir = op_dir / "new"
                if report_dir.exists():
                    json_file = report_dir / "estimates.json"
                    if json_file.exists():
                        mean_ms = extract_mean_ms(json_file)
                        if mean_ms is not None:
                            curve_data.append({
                                "curve": curve_name,
                                "implementation": impl,
                                "operation": operation,
                                "mean_ms": mean_ms
                            })
    
    return curve_data

def main():
    """Main function to extract all curve benchmark data and save results."""
    print(f"Extracting benchmark data from {BASE_DIR}")
    benchmark_df = extract_curve_benchmark_data(BASE_DIR)
    
    if benchmark_df.empty:
        print("No data found. Please ensure benchmarks have been run.")
        return
    
    # Create extracts directory if it doesn't exist
    os.makedirs("extracts", exist_ok=True)
    
    # Save to CSV in extracts directory
    csv_file = "extracts/vrf_curve_benchmarks.csv"
    benchmark_df.to_csv(csv_file, index=False)
    print(f"Benchmark data successfully saved to {csv_file}")
    
    # Print basic information
    print(f"\nExtracted {benchmark_df.shape[0]} benchmark data points")
    print(f"Curves: {benchmark_df['curve'].unique()}")
    print(f"Implementations: {benchmark_df['implementation'].unique()}")
    
    # Generate comparison summaries
    print("\nSummary of mean execution times by curve and implementation (ms):")
    curve_summary = benchmark_df.pivot_table(
        index=['curve', 'implementation'],
        columns='operation', 
        values='mean_ms',
        aggfunc='mean'
    )
    print(curve_summary)
    
    # Save the summary table
    summary_csv = "extracts/vrf_curve_summary.csv"
    curve_summary.to_csv(summary_csv)
    print(f"\nDetailed summary saved to {summary_csv}")
    
    # Generate comparison across curves for each implementation
    print("\nPerformance comparison across curves:")
    pairing_free_impls = ['dy_pf', 'dy_pf_priv', 'dy_pf_priv_commited_output']
    
    for impl in pairing_free_impls:
        impl_data = benchmark_df[benchmark_df['implementation'].str.contains(impl)]
        if not impl_data.empty:
            print(f"\n{impl} implementation:")
            impl_summary = impl_data.pivot_table(
                index='curve',
                columns='operation', 
                values='mean_ms',
                aggfunc='mean'
            )
            print(impl_summary)

if __name__ == "__main__":
    main()