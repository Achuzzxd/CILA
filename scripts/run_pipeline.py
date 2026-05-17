import os
import sys
import subprocess
import time

def run_step(command, step_name):
    print(f"\n--- Starting Step: {step_name}")
    print(f"Command: {command}")
    try:
        start_time = time.time()
        # Use sys.executable to ensure we use the same python interpreter
        process = subprocess.Popen([sys.executable] + command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
        
        for line in process.stdout:
            print(f"  [{step_name}] {line.strip()}")
            
        process.wait()
        duration = time.time() - start_time
        
        if process.returncode == 0:
            print(f"CHECK Step '{step_name}' completed successfully in {duration:.2f}s.")
            return True
        else:
            print(f"X Step '{step_name}' failed with exit code {process.returncode}.")
            return False
    except Exception as e:
        print(f"X Error running step '{step_name}': {e}")
        return False

def run_pipeline():
    print("====================================================")
    print("CLIA End-to-End Pipeline Automation")
    print("====================================================")
    
    steps = [
        ("scripts/run_ingestion.py", "Data Ingestion & Normalization"),
        ("scripts/fine_tune_ocsvm.py", "Model Fine-Tuning & Re-training"),
        ("scripts/evaluator.py", "Model Evaluation & Metrics Generation")
    ]
    
    all_success = True
    for cmd, name in steps:
        if not run_step(cmd, name):
            all_success = False
            print("\nPIPELINE halted due to error in mandatory step.")
            break
            
    if all_success:
        print("\n====================================================")
        print("Pipeline Complete! System is now up-to-date.")
        print("   Database synced, model re-trained, and reports generated.")
        print("====================================================")
    else:
        sys.exit(1)

if __name__ == "__main__":
    run_pipeline()
