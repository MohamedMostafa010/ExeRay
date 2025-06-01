# malware_detector/scripts/extract_features.py
import pefile
import pandas as pd # For creating and saving a structured dataset.
import os
import numpy as np # For numerical calculations like entropy and averages.
import re

DATA_DIR = "../data"
OUTPUT_FILE = "../output/malware_dataset.csv"

def get_strings(filepath, min_length=4): # Very short strings (like 1, 2, or 3 characters) are often too common and meaningless.
    with open(filepath, 'rb') as f:
        data = f.read()
    pattern = rb'[\x20-\x7E]{%d,}' % min_length
    return re.findall(pattern, data) # Using rb'' means the pattern is a bytes object, and re.findall works with bytes read from the file.

def extract_features(filepath):
    try:
        pe = pefile.PE(filepath) # Parsing Phase.
        section_names = [s.Name.decode(errors='ignore').rstrip('\x00') for s in pe.sections]
        
        '''
        - Shannon entropy is a measure of uncertainty or randomness in a set of data, introduced by Claude Shannon in 1948. It's a fundamental concept in information theory, often
        used to quantify how much information is in a message or how predictable a set of outcomes is.
        '''
        counts = [section_names.count(name) for name in set(section_names)]
        probs = [count / len(section_names) for count in counts]
        section_names_entropy = -sum(p * np.log2(p) for p in probs) if probs else 0
    
        # Imports info
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'): # built-in Python function that checks if an object has a specific attribute.
            dll_names = [entry.dll.decode(errors='ignore') for entry in pe.DIRECTORY_ENTRY_IMPORT]
            num_imports = len(dll_names)
            num_unique_dlls = len(set(dll_names))
        else:
            num_imports = 0
            num_unique_dlls = 0
        
        characteristics = pe.FILE_HEADER.Characteristics # The PE header contains a 2-byte flag called Characteristics.
        
        strings = get_strings(filepath)
        num_strings = len(strings)
        avg_string_length = np.mean([len(s) for s in strings]) if strings else 0
        
        features = {
            'size': os.path.getsize(filepath),
            'num_sections': len(pe.sections),
            'num_unique_sections': len(set(section_names)),
            'section_names_entropy': section_names_entropy,
            'num_imports': num_imports,
            'num_unique_dlls': num_unique_dlls,
            'is_dll': int(characteristics & 0x2000),
            'is_executable': int(characteristics & 0x0002),
            'is_system_file': int(characteristics & 0x1000),
            'avg_entropy': np.mean([s.get_entropy() for s in pe.sections]),
            'num_strings': num_strings,
            'avg_string_length': avg_string_length
        }
        pe.close() # If you don’t call pe.close(), the file might stay open in your program, which can lead to resource leaks (too many files open at once).
        return features
    except Exception as e:
        # print(f"[!] Error extracting features from {filepath}: {e}")
        return None

def build_dataset():
    data = []
    limit = 120  # Limit per class
    for label, dir_name in [("malicious", "malware"), ("benign", "benign")]:
        path = os.path.join(DATA_DIR, dir_name)
        if not os.path.exists(path):
            print(f"[!] Directory not found: {path}")
            continue

        count = 0
        for file in os.listdir(path):
            if count >= limit:
                break
            full_path = os.path.join(path, file)
            features = extract_features(full_path)
            if features:
                features["label"] = 1 if label == "malicious" else 0
                data.append(features)
                count += 1

    df = pd.DataFrame(data) # pd.DataFrame(data) returns a DataFrame object — which is basically a table-like data structure with rows and columns.
    df.to_csv(OUTPUT_FILE, index=False) # index=False tells pandas not to write these row numbers to the CSV.
    print(f"Dataset saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    build_dataset()

