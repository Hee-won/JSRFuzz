import csv
import os
from collections import defaultdict

def get_folder_names(folder_path):
    """특정 폴더의 모든 하위 폴더 이름을 반환합니다."""
    return [name for name in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, name))]

def match_names(name12, folder_names):
    """CSV의 이름과 폴더 이름을 매칭하고 결과를 반환합니다."""
    match_counts = defaultdict(int)
    matches = []

    # ' (' 문자가 포함되어 있는지 확인합니다.
    if ' (' in name12:
        name1, name2 = name12.split(' (')
        name2 = name2.rstrip(')')
    else:
        print(f"Invalid format for name12: {name12}")
        return matches, match_counts

    for folder_name in folder_names:
        if '##' in folder_name:
            name3, name4 = folder_name.split('##')
        else:
            continue

        if (name1 == name3 or name1 == name4 or name2 == name3 or name2 == name4):
            matches.append((name12, folder_name))
            match_counts[(name12, folder_name)] += 1

    return matches, match_counts

def main(csv_file_path, folder_path):
    all_matches = []
    all_match_counts = defaultdict(int)
    unmatched_packages = []
    
    with open(csv_file_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # 첫번째 행 제외 (헤더라인)
        folder_names = get_folder_names(folder_path)
        
        for row in reader:
            name12 = row[1]  # 두번째 열
            print(f"Processing: {name12}")
    
            matches, match_counts = match_names(name12, folder_names)
            if not matches:
                unmatched_packages.append(name12)
            else:
                all_matches.extend(matches)
                for match, count in match_counts.items():
                    all_match_counts[match] += count
    
    print("\nMatches:")
    for match in all_matches:
        print(f"{match[0]} <=> {match[1]}")

    print("\nMatch Counts:")
    for match, count in all_match_counts.items():
        print(f"{match[0]} <=> {match[1]}: {count} times")

    print("\nUnmatched Packages:")
    for package in unmatched_packages:
        print(package)
    print(f"Total Unmatched Packages: {len(unmatched_packages)}")

if __name__ == "__main__":
    csv_file_path = 'IoTcube_VDB_JS.csv'
    folder_path = 'vul_js'
    main(csv_file_path, folder_path)
