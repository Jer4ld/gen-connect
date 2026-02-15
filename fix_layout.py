
file_path = r'c:\Users\Admin\IT1825\gen-connect-main\gen-connect\templates\activities-home.html'

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Lines to remove are 647 to 707 (1-based index)
# In 0-based index: 646 to 707 (exclusive? no, inclusive)
# Python slice: [646:707] will remove 647 to 707?
# Line 647 is index 646.
# Line 707 is index 706.
# So we want to keep lines[:646] and lines[707:]

new_lines = lines[:646] + lines[707:]

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("Successfully removed lines 647-707.")
