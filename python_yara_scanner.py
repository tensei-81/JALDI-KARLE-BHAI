import yara
import os

class MalwareScanner:
    def __init__(self, rules_file):
        self.rules = yara.compile(filepath=rules_file)

    def scan_file(self, file_path):
        try:
            matches = self.rules.match(filepath=file_path)
            if matches:
                print(f"Malware detected in {file_path}:")
                for match in matches:
                    print(f"  Rule: {match.rule}, Description: {match.meta.get('description', 'No description')}")
            else:
                print(f"No malware detected in {file_path}")
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")

    def scan_directory(self, directory):
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                self.scan_file(file_path)

if __name__ == "__main__":
    # Path to the YARA rules file
    rules_file = "rules_APT.yar"
    
    # Initialize the scanner
    scanner = MalwareScanner(rules_file)
    
    # Scan a specific file or directory
    target_path = r"C:\Users\kingh\Downloads\yara-v4.5.2-2326-win64\NEW RULES"  # Replace with the file or directory you want to scan
    if os.path.isfile(target_path):
        scanner.scan_file(target_path)
    elif os.path.isdir(target_path):
        scanner.scan_directory(target_path)
    else:
        print(f"The path {target_path} does not exist.")