# Name: Tanner Lancaster tsl0074
#Denial of Service: Docker and Host Machine POC
#CSCE 3650 cloud security
# Project 



# memory exhaustion monitoring
import psutil
from datetime import datetime, timedelta
import time
import logging
import os
import signal

# basic logging configuration using the library 'logging' this fixes the format and message output in file 'memory.log'
logging.basicConfig(
    filename="RAM.log",
    encoding="utf-8",
    filemode="a",
    level=logging.INFO,
    format='[%(levelname)s] | [%(asctime)s] | %(message)s]'
)

# you will see duplicate messages. this is because messages are outputed in terminal and in logs
logging.info("IDPS is running...")
print(f"[INFO] IDPS is running...")
logging.info("Memory Monitorization/Detection/Prevention has started...") 
print(f"[INFO] Memory Monitorization/Detection/Prevention has started...")

# ++++++++++++++++++++ Memory Exhaustion Detection/Prevention Section +++++++++++++++++++++++++ #

# progress bar for the memory use monitorization
def progress(memory):
    ram = (memory/100.0) # if left without the /100, the memory would immediately cap the rules, and come off as over 100% ram usage, when that's not the case. 
    ram2 = ram * 100 # Debug error. output would display 0.20% rather than 20.0%. this fixes that issue.
    ten_percent_margin = 30
    
    memory_load = '#' * int(ram*ten_percent_margin) + '=' * (ten_percent_margin - int(ram*ten_percent_margin)) # this outputs the percentage bar on the terminal
    print(f"\rMemory (live): |{memory_load}| {ram2:.2f}%  ", end="") # the end="" keeps the cursor as a one liner, instead of repeatedly outputing the message

# used in function: RAM_IDPS()
def rapid_progression():
    current_memory = psutil.virtual_memory().percent # grab current memory percentage
    current_time = datetime.now() # mark the time start
    time.sleep(3) # wait 3 seconds
    new_memory = psutil.virtual_memory().percent
    new_time = datetime.now()
        
    mem_threshold = new_memory - current_memory # subtract new memory and old memory to get the displacement
    threshold = timedelta(seconds=3) # do the same with the current time to grab seconds
    time_check = abs(current_time - new_time)
        
    # anomaly rule #2: growth progression
    if mem_threshold >= 0.08 and time_check >= threshold: # if the memory use jumps up 8%, send a 'possible growth' alert
        print(f"[WARNING]** Memory usage jumped by 8% {threshold} seconds. Memory: {psutil.virtual_memory().percent}%. Growth progression Detected!")
        logging.warning(f"** Memory usage jumped by 8% within {threshold} seconds. Memory: {psutil.virtual_memory().percent}%. Growth progression Detected!")
    else:
        print("[INFO][TEST] No growth Detected. Rapid Growth Progression test ended.  ")
        logging.info("[TEST] No growth Detected. Rapid Growth Progression test ended.  ")

# this will create a list of pid's running on the system        
def process_get_list():    
    list_process = []  # list of pid's for checking cpu and memory overhead anomaly 
    for p in psutil.process_iter(attrs=['pid', 'memory_info', 'name']):
        try:
            proc_mem = p.info["memory_info"].rss
            proc_id = p.info["pid"]
            proc_name = p.info["name"]
            pid_list = (proc_id, proc_mem, proc_name) # we create a tuple that will be repeatedly added to the pid dictionary
            list_process.append(pid_list) # add the process data to the list      
        except psutil.NoSuchProcess:
            pass 
    return list_process # we will return the dictionary with the added tuple memory data       
        
# main detection/prevention function                
def RAM_IDPS(memory, cpu):
    
    message_sent_first_anomaly = False # make sure the message only prints out once. if false, print message. if true, don't print message for each rule
    message_sent_second_anomaly = False
    message_sent_third_anomaly = False
    message_sent_fourth_anomaly = False
    message_growth = False
    critical_growth = False
    process_kill = False
    mem = (memory/100.0) # for more information on this logic, visit the progress function at the top
    mem2 = mem * 100
    c = cpu
    
    # first anomaly rule (if percentage caps over 70%, send a warning message and check for agreesive growth changes)
    if mem >= 0.70 and mem < 0.80 and message_sent_first_anomaly == False:
        print(f"")
        print(f"")
        logging.warning(f"** Memory use has exceeded 70%. Current Memory: {mem2:.2f}%. Monitoring in Progress...")
        print(f"**[WARNING] Memory use has exceeded 70%. Current Memory: {mem2:.2f}%  Monitoring in Progress...")
        message_sent_first_anomaly = True

    # anomaly rule #2 checking for rapid growth progression, we will call the function above to compare old and new values for both time and memory percentage
    if message_growth == False and mem >= 0.75 and mem < 0.85:
        print(f"[INFO][TEST] Memory has exceeded 75%. Current Memory: {mem2:.2f}%. Running Rapid Growth Progression Detection...")
        logging.info(f"[TEST] Memory has exceeded 75%. Current Memory: {mem2:.2f}%. Running Rapid Growth Progression Detection...")
        time.sleep(0.5)
        rapid_progression()
        print(f"")
        message_growth = True
                  
    #anomaly rule #3 ( if percentage caps over 80%, send another warning, check for growth, locate pid, and check if the process's memory grows by more than 8% )
    if mem >= 0.80 and mem < 0.90 and message_sent_second_anomaly == False:
        print(f"")
        logging.critical(f"** Memory use has exceeded 80%. Current Memory: {mem2:.2f}%. Identifying Process...")
        print(f"[CRITICAL] ** Memory use has exceeded 80%. Current Memory: {mem2:.2f}%. Identifying Process...")
        print(f"")
        p_list = process_get_list()
        p_list.sort(key=lambda x: x[1], reverse=True) #sort tuples by highest memory [0] - pid, [1] - memory, [2] - name
        f_pid = p_list[0]
        print(f"[ALERT] PID: {f_pid[0]} Name: {f_pid[2]} | Process causing memory overuse.")
        logging.critical(f"[ALERT] PID: {f_pid[0]} Name: {f_pid[2]} | Process causing memory overuse.")
        message_sent_second_anomaly = True

        # checking for rapid growth progression, we will call the function above to compare old and new values for both time and memory percentage
        if critical_growth == False and mem >= 0.80:
            print(f"")
            print(f"[WARNING][TEST] Memory exceeded 80%. DoS? Running Process Growth Progression Detection...")
            logging.warning("[TEST] Memory exceeded 80%. DoS? Running Process Growth Progression Detection...")
            
            ram_grab_one = f_pid[1] # grab current memory percentage of suspicious process
            new_pid = psutil.Process(f_pid[0]) # grab the process ID 
            time_grab_one = datetime.now() # mark the time start
            time.sleep(3) # wait 3 seconds
            ram_grab_two = new_pid.memory_info().rss
            time_grab_two = datetime.now()
        
            ram_threshold = ram_grab_two - ram_grab_one # subtract new memory and old memory to get the displacement
            time_threshold = timedelta(seconds=3) # do the same with the current time to grab seconds
            time_verify = abs(time_grab_one - time_grab_two)
        
            # anomaly rule #3: Process growth progression
            if ram_threshold >= 0.06 and time_verify >= time_threshold: # if the memory use jumps up 6%, send a 'possible growth' alert
                print(f"[WARNING]** Detected growth coming from PID: {f_pid[0]} Name: {f_pid[2]} DoS?")
                logging.warning(f"** Detected growth coming from PID: {f_pid[0]} Name: {f_pid[2]} DoS?")
            else:
                print("[INFO][TEST] No growth detected from process list. Process Growth Progression test ended.  ")
                logging.info(" [TEST] No growth detected from process list. Rapid Growth Progression test ended.  ")           
            print(f"")
            critical_growth = True
 
    # anomaly rule #4: If memory use reaches 90% Check for the process running the highest memory usage. Intrusion Prevention will identify the pid, memory %, name of script running and terminate 
    if mem >= 0.90 and message_sent_fourth_anomaly == False and process_kill == False:
        print(f"[CRITICAL][TEST] Memory use has exceeded 90%. Current Memory: {mem2:.2f}%.  ")
        logging.critical(f"[TEST] Memory use has exceeded 90%. Current Memory: {mem2:.2f}%.  ")
        time.sleep(0.5)
        
        new_list = process_get_list() # call list of pid's we grabbed from the process list function
        print(f"[INFO][TEST] Analyzing suspicious memory use from running processes... ")
        logging.info("[TEST] Analyzing suspicious memory use from running processes... ")
        message_sent_fourth_anomaly = True
        
        time.sleep(0.5)
        new_list.sort(key=lambda x: x[1], reverse=True) #sort tuples by highest memory [0] - pid, [1] - memory, [2] - name
        found_pid = new_list[0] # grab the top process in the list
        print(f"[CRITICAL][ALERT] PID: {found_pid[0]} Memory Use: {found_pid[1]} Name: {found_pid[2]} | Process Found! Terminating Now!")
        logging.critical(f"[ALERT] PID: {found_pid[0]} Memory Use: {found_pid[1]} Name: {found_pid[2]} | Process Found! Terminating Now!")
        time.sleep(0.5)
        os.kill(found_pid[0], signal.SIGTERM) #kill process
        logging.info(f"[ALERT] Malicious Process: {found_pid[0]} Name: {found_pid[2]} | Was terminated Successfully. Monitoring in progress...")
        print(f"[INFO][ALERT] Malicious Process: {found_pid[0]} Name: {found_pid[2]} | Was terminated Successfully. Monitoring in progress...")
        process_kill = True
        print("")
        
              
    # reset the boolean expressions incase the memory drops back down after Successful DOS prevention
    if mem < 0.65 and message_sent_first_anomaly == True:
        message_sent_first_anomaly = False
    if mem < 0.65 and message_sent_second_anomaly == True:
        message_sent_second_anomaly = False
    if mem < 0.65 and message_sent_third_anomaly == True:
        message_sent_third_anomaly = False
    if mem < 0.65 and message_growth == True:
        message_growth = False
    if mem < 0.65 and message_sent_fourth_anomaly == True:
        message_sent_fourth_anomaly = False
    if mem < 0.65 and process_kill == True:
        process_kill = False

# ++++++++++++++++++++ Memory Exhaustion Detection/Prevention Section +++++++++++++++++++++++++ #

# the main loop for running IDPS. other dos functions should be called here. to test, simply comment out everything else in here but your functions and calls. just make sure to uncomment before project submission!    
while True:
    progress(psutil.virtual_memory().percent) #execute progress bar
    time.sleep(0.5)
    
    RAM_IDPS(psutil.virtual_memory().percent, psutil.cpu_percent()) # start monitoring
    time.sleep(10) # wait before executing loop again
    
    
        
