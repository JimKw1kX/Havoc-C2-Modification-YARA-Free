import os
import sys
import subprocess


directory = ('C:\\Users\\User\\Downloads\\Mem_Scan\\protections-artifacts-main\\protections-artifacts-main\\yara\\rules')
target = 'C:\\Users\\User\\Desktop\\Payloads\\Products\\double_module_stomp\\PayloadLoader\\x64\\Release\\DllLoader.dll'

for fileanme in os.listdir(directory):
    filepath = os.path.join(directory, fileanme)

    if os.path.isfile(filepath):
        cmd = ['yara64.exe','-s', filepath, target]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            with open('yara_loader_result.txt', 'a') as f:
                outout = f'Detected===>!!!\\n{filepath} ====>\n {result.stdout}'
                print(outout)