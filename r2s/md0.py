#!/usr/bin/env python
import subprocess
from tqdm import tqdm

for i in tqdm(range(20)):
    cmd = f'tshark -nr dump.pcap -z follow,tcp,raw,{i} -Y ftp'.split()
    result = str(subprocess.check_output(cmd)).split('===================================================================')
    result = result[1]
    
    # drop first line
    index = 0
    for k in range(5):
        index = result.find('\\n', index) + 2
    result = result[index:]
    #print(result)

    result = result.replace('\\n','').replace('\\t','')

    n = 2
    with open(f"file{i}.mp4", "wb") as f:
        for j in tqdm([result[k:k+n] for k in range(0, len(result), n)]):
            f.write(int(j, 16).to_bytes(1, byteorder="little"))

