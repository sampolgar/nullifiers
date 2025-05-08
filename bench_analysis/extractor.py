import json
import pandas as pd
from pathlib import Path
import os

# Define the base directory for Criterion benchmark results
BASE_DIR = Path("target/criterion")
# BASE_DIR = Path("../../target/criterion")

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

def extract_benchmark_data(base_dir: Path) -> pd.DataFrame:
    """Extract VRF benchmark data from Criterion directories and return a DataFrame."""
    all_data = []
    
    # Check if base directory exists
    if not base_dir.exists():
        print(f"Error: Base directory {base_dir} does not exist!")
        return pd.DataFrame()
    
    # VRF implementations we expect to find
    vrf_implementations = ['dy', 'dy_pf', 'dy_pf_priv', 'dy_pf_priv_commited_output', 'dy_priv']
    
    for impl in vrf_implementations:
        impl_dir = base_dir / impl
        if not impl_dir.exists() or not impl_dir.is_dir():
            print(f"Warning: Implementation directory {impl} not found")
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
                        all_data.append({
                            "implementation": impl,
                            "operation": operation_label,
                            "mean_ms": mean_ms
                        })
    
    if not all_data:
        print("No benchmark data found in the specified directory!")
        return pd.DataFrame()
    
    df = pd.DataFrame(all_data)
    return df.sort_values(["implementation", "operation"])

def main():
    """Main function to extract benchmark data and save results."""
    print(f"Extracting benchmark data from {BASE_DIR}")
    benchmark_df = extract_benchmark_data(BASE_DIR)
    
    if benchmark_df.empty:
        print("No data found. Please ensure benchmarks have been run.")
        return
    
    # Create extracts directory if it doesn't exist
    os.makedirs("extracts", exist_ok=True)
    
    # Save to CSV in extracts directory
    csv_file = "extracts/vrf_benchmarks.csv"
    benchmark_df.to_csv(csv_file, index=False)
    print(f"Benchmark data successfully saved to {csv_file}")
    
    # Print basic information
    print(f"\nExtracted {benchmark_df.shape[0]} benchmark data points")
    print(f"Implementations: {benchmark_df['implementation'].unique()}")
    print("\nSummary of mean execution times (ms):")
    summary = benchmark_df.pivot_table(
        index='implementation', 
        columns='operation', 
        values='mean_ms',
        aggfunc='mean'
    )
    print(summary)

if __name__ == "__main__":
    main()