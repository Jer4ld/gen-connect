import os

path = r'c:\Users\Admin\IT1825\gen-connect-main\gen-connect\templates\myactivities.html'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the spaces
new_content = content.replace('{ {', '{{').replace('} }', '}}')

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print("Successfully fixed myactivities.html")
