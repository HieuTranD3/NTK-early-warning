#!/usr/bin/env python3
import sys
from pathlib import Path

# Add the parent directory to sys.path to allow imports from modules folder
sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules import utils
from modules import baseline_scan
from modules import nuclei_scan

def menu():
    while True:
        print("\n====================================================")
        print(" NTK - Early Vulnerability Warning Tool")
        print("====================================================")
        print("[1] Run baseline scan and build service inventory")
        print("[2] Run Nuclei all CVE templates + parse output")
        print("[3] Update Nuclei + templates")
        print("[4] Check project folder / target / nuclei")
        print("[0] Exit")
        print("====================================================")

        choice = input("Select option: ").strip()

        if choice == "1":
            baseline_scan.run_baseline()
        elif choice == "2":
            nuclei_scan.run_scan()
        elif choice == "3":
            utils.update_nuclei_and_templates()
        elif choice == "4":
            utils.check_structure()
        elif choice == "0":
            print("Exit.")
            break
        else:
            print("[ERROR] Invalid option.")

if __name__ == "__main__":
    menu()
