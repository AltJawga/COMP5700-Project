import os
import argparse
import extractor
import comparator
import executor


if __name__ == "__main__":
    print("Start with extractor input cis pdfs!")
    parser = argparse.ArgumentParser(description="Process two file paths.")
    parser.add_argument("path1", type=str, help="First path (string)")
    parser.add_argument("path2", type=str, help="Second path (string)")
    args = parser.parse_args()

    pdf1 = os.path.splitext(os.path.basename(args.path1))[0]
    pdf2 = os.path.splitext(os.path.basename(args.path2))[0]
    print(f"Received pdfs: {pdf1} and {pdf2}")

    # ----------- Extractor ----------- #
    print("=" * 50)
    print(f"Running the extractor pipeline with {args.path1} and {args.path2}")
    extractor.run_extraction_pipeline(args.path1, args.path2)
    print("Extractor pipeline completed successfully!")
    print("=" * 50)

    # ----------- Comparator ----------- #
    # YAML outputs are saved in the project root, not in static
    yaml1name = f"{os.path.splitext(os.path.basename(args.path1))[0]}-kdes.yaml"
    yaml2name = f"{os.path.splitext(os.path.basename(args.path2))[0]}-kdes.yaml"
    yaml1path = os.path.join(os.path.dirname(__file__), yaml1name)
    yaml2path = os.path.join(os.path.dirname(__file__), yaml2name)
    print(f"Running the comparator pipeline with {yaml1path} and {yaml2path}")
    comparator.run_comparator_pipeline(yaml1path, yaml2path)
    print("Comparator pipeline completed successfully!")
    print("=" * 50)

    # ----------- Executor ----------- #
    name_diff_file_name = f"name_differences_{os.path.splitext(os.path.basename(args.path1))[0]}_vs_{os.path.splitext(os.path.basename(args.path2))[0]}.txt"
    req_diff_file_name = f"requirement_differences_{os.path.splitext(os.path.basename(args.path1))[0]}_vs_{os.path.splitext(os.path.basename(args.path2))[0]}.txt"
    
    name_diff_path = os.path.join(os.path.dirname(__file__), name_diff_file_name)
    req_diff_path = os.path.join(os.path.dirname(__file__), req_diff_file_name)
    print(f"Running the executor pipeline with {name_diff_path} and {req_diff_path}")
    executor.run_execution_pipeline(name_diff_path, req_diff_path, output_csv=f"kubescape_results_{pdf1}_vs_{pdf2}.csv")
    print("Executor pipeline completed successfully!")
    print("=" * 50)


