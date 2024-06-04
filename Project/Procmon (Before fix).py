import sys
import os
import csv
import evtx_dump
from datetime import datetime
import ctypes
import subprocess
from subprocess import Popen
try:
 is_admin = os.getuid() == 0
except AttributeError:
 is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
if is_admin == True:
    print("The program is running in Administrator mode")
else:
    print("The program is not running in Adminstrator mode! Restart the tool and run it as Admin")
    input("Enter any key to exit")
    exit()
'''
NOTE: PATHS MUST BE CHANGED TO MAKE PROGRAM USABLE!!
'''
input("This Script will clear all Event Logs in your system. Enter anything to continue:")
os.system("for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"")
#To detect the module, make sure the path to the script folder is added to sys.path as shown below
sys.path.append(".")

print("The program will now scan the Event Log Files")
#First Scan
first = str(input("Enter 'y' for first scan:"))
if first == 'y':
    firstrecordlist = []
    etlfilelist=[]
    replacelist = []
    filelist=[]
    counter = 0
    pointer = 0
    directory = 'C:\\Windows\\System32\\winevt\\Logs' #Directory to Event Logs
#Using a loop to save all file names and number of logs per evtx file into lists
    for filename in os.listdir(directory):
        if filename.endswith(".evtx"):
            filelist.append(filename)
            os.system("FullEventLogView.exe /scomma \""+filename+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+filename+"\""+ " /EventIDFilter 3 /EventIDFilterStr \"5152,5379,5382,1151,1002,104,1001,1000,2000\"")
            checkfile = open(r".\\"+filename+".csv")
            checkreader = csv.reader(checkfile)
            checklines = len(list(checkreader))
            firstrecordlist.append(checklines-1)
            checkfile.close()
            os.remove(filename+".csv")
        elif filename.endswith(".etl"):
            etlfilelist.append(filename)
        else:
            continue
#Replacing Slashes and ".etl" extensions in the ETL List
#So that disabling and reenabling the logs can be done
    replacelist = etlfilelist
    for i in replacelist:
        if '%4' in i:
            i = i.replace('%4','/')
            i = i.replace('.etl','')
            replacelist[counter] = i
            counter+=1
        else:
            i = i.replace('.etl','')
            replacelist[counter] = i
            counter+=1
#disable and enable the logs to start with a clean slate
    for i in replacelist:
        os.system("wevtutil.exe sl "+i+" /e:false")
        print("Enter Y for the next Question")
        os.system("wevtutil.exe sl "+i+" /e:true")
    print("First Scan Completed")

#First Scan of Prefetch Files (Creating a list of all prefetch file names and a list of all modification dates
    firstprefetchnamelist = []
    firstprefetchmodifylist = []
    for filename in os.listdir("C:\\Windows\\Prefetch"):
        if filename.endswith(".pf"):
            firstprefetchnamelist.append(filename)
            firstprefetchmodifylist.append(datetime.fromtimestamp(os.path.getmtime("C:\\Windows\\Prefetch\\"+filename)).strftime('%Y-%m-%d %H:%M:%S'))
        else:
            continue
#Starting Procmon for Second Scan
    print("Procmon will now start. You can perform testing now. After testing is completed, you MUST close the process monitor manually or the log file will be corrupted")
    os.system("procmon.exe /Minimized /Backingfile .\\test.pml")


#Second Scan
second = input("Enter 'y' for second scan:")
if second == 'y':
#Recording number of Prefetch files and their modification date
    secondprefetchnamelist = []
    secondprefetchmodifylist=[]
    newpflist = []
    pfchangeslist=[]
    for filename in os.listdir("C:\\Windows\\Prefetch"):
        if filename.endswith(".pf"):
            secondprefetchnamelist.append(filename)
            secondprefetchmodifylist.append(datetime.fromtimestamp(os.path.getmtime("C:\\Windows\\Prefetch\\"+filename)).strftime('%Y-%m-%d %H:%M:%S'))
        else:
            continue
    if len(secondprefetchnamelist) > len(firstprefetchnamelist):
        index = 0
        for i in secondprefetchnamelist:
            if i in firstprefetchnamelist:
                continue
            else:
                index = secondprefetchnamelist.index(i)
                secondprefetchmodifylist.pop(index)
                newpflist.append(i)
    else:
        pass

    counter = 0
    for i in firstprefetchmodifylist:
        if i >= secondprefetchmodifylist[counter]:
            counter+=1
        else:
            pfchangeslist.append(firstprefetchnamelist[counter])
            counter+=1

#Recording number of logs in each evtx file
    secondrecordlist=[]
    for filename in os.listdir(directory):
        if filename.endswith(".evtx"):
            os.system("FullEventLogView.exe /scomma \""+filename+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+filename+"\""+ " /EventIDFilter 3 /EventIDFilterStr \"5379,5382,1151,1002,104,1001,1000,2000\"")
            checkfile = open(r".\\"+filename+".csv")
            checkreader = csv.reader(checkfile)
            checklines = len(list(checkreader))
            secondrecordlist.append(checklines-1)
            checkfile.close()
            os.remove(filename+".csv")
        else:
            continue
#Comparing the values in record lists to see if any additional logs are generated
    pointer = 0
    evtxchangeslist = []
    for i in firstrecordlist:
        if secondrecordlist[pointer] > i:
            evtxchangeslist.append(filelist[pointer])
            pointer+=1
        else:
            pointer+=1
            pass

    counter = 0
    lines = 0
    file = None
    reader = None
    etlchangeslist = []
#Disabling the logs so that it is accessible
    for i in replacelist:
        os.system("wevtutil.exe sl "+i+" /e:false")

#Converting the ETL files to CSV files, analysing them to see if new logs are generated based on the number of lines in the csv files
    for filename in os.listdir(directory):
        if filename.endswith('.etl'):
            os.system("tracerpt "+"C:\\Windows\\System32\\winevt\\Logs\\"+filename+" -o logdump.csv -of CSV -y")
            file = open(r".\\logdump.csv")
            reader = csv.reader(file)
            lines = len(list(reader))
            if lines > 3:
                etlchangeslist.append(etlfilelist[counter])
            else:
                pass
            counter+=1
            file.close()
            os.remove("logdump.csv")
        else:
            continue

#Saving Prefetch File changes to text files
    if len(newpflist) == 0 and len(pfchangeslist) == 0:
        print("No changes detected in Prefetch files")
    else:
        pref = open(".\\Output\\Prefetch_Changes.txt","w+")
        pref.write("There is a very simple tool located in the Project Folder called winprefetchview. \nUse that to analyse and obtain more information about the Prefetch Files.\n\n")
        if len(newpflist) == 0:
            pass
        else:
            pref.write("New Prefetch Files were created:\n")
            for i in newpflist:
                pref.write(i + "\n")
        if len(pfchangeslist) == 0:
            pass
        else:
            pref.write("\nThe following prefetch files were modified. Take note of these files as they might have been edited manually:\n")
            for i in pfchangeslist:
                pref.write(i + "\n")
        pref.close()
        print("Prefetch File Changes are saved in Prefetch_Changes.txt")

#Saving Event Log changes to text files
    if len(evtxchangeslist) == 0:
        print("No new Event Logs were generated in the EVTX Files.")
    else:
        evtxf = open(".\\Output\\Evtx_Changes.txt","w+")
        evtxf.write("Event Logs were generated in:\n")
        for i in evtxchangeslist:
            evtxf.write(i + "\n")
        evtxf.close()
        print("Event Log Changes are saved in Evtx_Changes.txt")

    if len(etlchangeslist) == 0:
        print("No new Event Logs were generated in the ETL Files.")
    else:
        etlf = open(".\\Output\\Etl_Changes.txt","w+")
        etlf.write("Event Logs were generated in:\n")
        for i in etlchangeslist:
            etlf.write(i + "\n")
        etlf.close()
        print("Event Log Changes are saved in Etl_Changes.txt")

#Prompting user to print changes
    if len(evtxchangeslist) != 0 or len(etlchangeslist) != 0:
        printchanges = str(input("Would you like to print the changes?(y/n):"))
        if printchanges == "y":
            print("1)Print by default behavior\n2)Print all changes\n3)Print specified location")
            option = str(input("Select one of the options above:"))
            if option == "1":
                if len(evtxchangeslist) != 0:
                    for i in evtxchangeslist:
                        if i == "Security.evtx":
                            #Registry and File changes logs will be seperated from security.evtx
                            #All Event IDs related to registry and file changes will be filtered as shown in the command below
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+i+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+i+"\""+ " /EventIDFilter 3 /EventIDFilterStr \"4656,4663,4657,4658,4690,4659,4660,5379,5382,5152\"")
                            with open(".\\Output\\"+"Security.evtx.csv",encoding="utf8") as r:
                                reader = csv.reader(r)
                                lines = list(reader)
                            if len(lines) <= 2:
                                os.remove('.\\Output\\Security.evtx.csv')
                            #Another csv with only registry and file changes must be made so these logs can be seperated even further. This is because events such as 4660 can affect both registry and files.
                            pmllist =[]
                            pmltocsvlist=[]
                            num = 1
                            y = "FileChanges"+str(num)+".csv"
                            z = "RegistryChanges"+str(num)+".csv"
                            for filename in os.listdir("."):
                                if filename.endswith(".pml"):
                                    pmllist.append(filename)
                                else:
                                    continue
                            for i in pmllist:
                                pmltocsvlist.append(y)
                                pmltocsvlist.append(z)
                                os.system("procmon.exe /AcceptEula /Quiet /Openlog .\\"+i+" /LoadConfig .\\FileConfiguration.pmc /SaveApplyFilter /SaveAs "+y)
                                os.system("procmon.exe /AcceptEula /Quiet /Openlog .\\"+i+" /LoadConfig .\\RegConfiguration.pmc /SaveApplyFilter /SaveAs "+z)
                                num +=1
                                y = "FileChanges"+str(num)+".csv"
                                z = "RegistryChanges"+str(num)+".csv"
                            ans = str(input("Would you like to filter by Process Name? (y/n):"))
                            num = 0
                            if ans == 'y':
                                processname = str(input("Enter a process name:"))
                                for filename in os.listdir("."):
                                    if filename in pmltocsvlist:
                                        with open(".\\"+filename)as r:
                                            pmlreader = csv.reader(r)
                                            pmllines = list(pmlreader)
                                            for i in pmllines:
                                                if i[1] != processname and num != 0:
                                                    pmllines.remove(i)
                                                    num+=1
                                                else:
                                                    num+=1
                                                    pass
                                            writer = csv.writer(open(".\\Output\\"+filename,"w+",newline=""))
                                            writer.writerows(pmllines)
                                            num = 0
                                        del writer
                                        os.remove(".\\"+filename)
                                    else:
                                        pass
                                                    
                            else:
                                pass

                        elif i == "Microsoft-Windows-Windows Defender%4Operational.evtx":
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+i+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+i+"\""+ " /EventIDFilter 3 /EventIDFilterStr \"1151,1002,1001,1000,2000\"")
                        elif i == "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx":
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+i+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+i+"\"")
                        elif i == "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx":
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+i+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+i+"\"")
                        elif i == "Windows PowerShell.evtx":
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+i+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+i+"\"")
                        elif i == "Microsoft-Windows-PowerShell%4Operational.evtx":
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+i+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+i+"\"")
                        else:
                            pass
                if len(etlchangeslist) != 0:
                    for i in etlchangeslist:
                        a = i
                        a = a.replace('/','%4')
                        a = a + '.etl'
                        print(a)
                        os.system("tracerpt "+"C:\\Windows\\System32\\winevt\\Logs\\"+a+" -o .\\Output\\" + a +".csv -of CSV -y")
                        #Converting clock time
                        with open(".\\Output\\"+a+".csv",encoding="utf8") as r:
                            counter = 0
                            reader = csv.reader(r)
                            lines = list(reader)
                            while counter < len(lines):
                                if counter == 0:
                                    counter += 1
                                    pass
                                else:
                                    #Converting Clock time to readable timestamps
                                    clock = lines[counter][16]
                                    clock = clock.strip()
                                    clock = os.popen("w32tm.exe /ntte "+clock).read()
                                    clock.replace('\n','')
                                    lines[counter][16] = clock
                                    
                                    #Converting hex PIDs to int PIDs
                                    pid = lines[counter][9]
                                    pid = str(int(pid,16))
                                    lines[counter][9] = pid

                                    #Converting hex TIDs to int PIDs
                                    tid = lines[counter][10]
                                    tid = str(int(tid,16))
                                    lines[counter][10] = tid
                                    counter += 1
                            writer = csv.writer(open(".\\Output\\"+a+".csv","w",newline=""))
                            writer.writerows(lines)
                            del reader
                            del writer
                        
            elif option == "2":
                if len(evtxchangeslist) != 0:
                    for i in evtxchangeslist:
                        if i == "Security.evtx":
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+i+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+i+"\""+ " /EventIDFilter 3 /EventIDFilterStr \"4656,4663,4657,4658,4690,4659,4660,5379,5382,5152\"")
                            with open(".\\Output\\"+"Security.evtx.csv",encoding="utf8") as r:
                                reader = csv.reader(r)
                                lines = list(reader)
                            if len(lines) <= 2:
                                os.remove('.\\Output\\Security.evtx.csv')
                            pmllist =[]
                            pmltocsvlist=[]
                            num = 1
                            y = "FileChanges"+str(num)+".csv"
                            z = "RegistryChanges"+str(num)+".csv"
                            for filename in os.listdir("."):
                                if filename.endswith(".pml"):
                                    pmllist.append(filename)
                                else:
                                    continue
                            for i in pmllist:
                                pmltocsvlist.append(y)
                                pmltocsvlist.append(z)
                                os.system("procmon.exe /AcceptEula /Quiet /Openlog .\\"+i+" /LoadConfig .\\FileConfiguration.pmc /SaveApplyFilter /SaveAs .\\Output\\"+y)
                                os.system("procmon.exe /AcceptEula /Quiet /Openlog .\\"+i+" /LoadConfig .\\RegConfiguration.pmc /SaveApplyFilter /SaveAs .\\Output\\"+z)
                                num +=1
                                y = "FileChanges"+str(num)+".csv"
                                z = "RegistryChanges"+str(num)+".csv"                                                  
                        else:
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+i+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+i+"\"")
                    
                if len(etlchangeslist) != 0:
                    for i in etlchangeslist:
                        a = i
                        a = a.replace('/','%4')
                        a = a + '.etl'
                        print(a)
                        os.system("tracerpt "+"C:\\Windows\\System32\\winevt\\Logs\\"+a+" -o .\\Output\\" + a +".csv -of CSV -y")

                        #Converting Information to make forensic analysis easier
                        with open(".\\Output\\"+a+".csv",encoding="utf8") as r:
                            counter = 0
                            reader = csv.reader(r)
                            lines = list(reader)
                            while counter < len(lines):
                                if counter == 0:
                                    counter += 1
                                    pass
                                else:
                                    #Converting Clock time to readable timestamps
                                    clock = lines[counter][16]
                                    clock = clock.strip()
                                    clock = os.popen("w32tm.exe /ntte "+clock).read()
                                    clock.replace('\n','')
                                    lines[counter][16] = clock
                                    
                                    #Converting hex PIDs to int PIDs
                                    pid = lines[counter][9]
                                    pid = str(int(pid,16))
                                    lines[counter][9] = pid

                                    #Converting hex TIDs to int PIDs
                                    tid = lines[counter][10]
                                    tid = str(int(tid,16))
                                    lines[counter][10] = tid
                                    counter += 1
                            writer = csv.writer(open(".\\Output\\"+a+".csv","w",newline=""))
                            writer.writerows(lines)
                            del reader
                            del writer
            else:
                flag = True
                while flag == True:
                    specified = str(input("Enter a log file to extract:"))
                    if specified.endswith('.etl'):
                        os.system("tracerpt "+"C:\\Windows\\System32\\winevt\\Logs\\"+specified+" -o .\\Output\\" + specified +".csv -of CSV -y")
                        #Converting clock time
                        with open(".\\Output\\"+specified+".csv",encoding="utf8") as r:
                            counter = 0
                            reader = csv.reader(r)
                            lines = list(reader)
                            while counter < len(lines):
                                if counter == 0:
                                    counter += 1
                                    pass
                                else:
                                    #Converting Clock time to readable timestamps
                                    clock = lines[counter][16]
                                    clock = clock.strip()
                                    clock = os.popen("w32tm.exe /ntte "+clock).read()
                                    clock.replace('\n','')
                                    lines[counter][16] = clock

                                    #Converting hex PIDs to int PIDs
                                    pid = lines[counter][9]
                                    pid = str(int(pid,16))
                                    lines[counter][9] = pid

                                    #Converting hex TIDs to int PIDs
                                    tid = lines[counter][10]
                                    tid = str(int(tid,16))
                                    lines[counter][10] = tid
                                    counter += 1
                            writer = csv.writer(open(".\\Output\\"+specified+".csv","w",newline=""))
                            writer.writerows(lines)
                            del reader
                            del writer
                        ans = str(input("Do you want to extract another file(y/n):"))
                        if ans == 'y':
                            continue
                        else:
                            flag = False
                    elif specified.endswith('evtx'):
                        if specified == "Security.evtx":
                            #Registry and File changes logs will be seperated from security.evtx
                            #All Event IDs related to registry and file changes will be filtered as shown in the command below
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+specified+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+specified+"\""+ " /EventIDFilter 3 /EventIDFilterStr \"4656,4663,4657,4658,4690,4659,4660,5379,5382,5152\"")
                            with open(".\\Output\\"+"Security.evtx.csv",encoding="utf8") as r:
                                reader = csv.reader(r)
                                lines = list(reader)
                            if len(lines) <= 2:
                                os.remove('.\\Output\\Security.evtx.csv')
                            #Another csv with only registry and file changes must be made so these logs can be seperated even further. This is because events such as 4660 can affect both registry and files.
                            pmllist =[]
                            pmltocsvlist=[]
                            num = 1
                            y = "FileChanges"+str(num)+".csv"
                            z = "RegistryChanges"+str(num)+".csv"
                            for filename in os.listdir("."):
                                if filename.endswith(".pml"):
                                    pmllist.append(filename)
                                else:
                                    continue
                            for i in pmllist:
                                pmltocsvlist.append(y)
                                pmltocsvlist.append(z)
                                os.system("procmon.exe /AcceptEula /Quiet /Openlog .\\"+i+" /LoadConfig .\\FileConfiguration.pmc /SaveApplyFilter /SaveAs "+y)
                                os.system("procmon.exe /AcceptEula /Quiet /Openlog .\\"+i+" /LoadConfig .\\RegConfiguration.pmc /SaveApplyFilter /SaveAs "+z)
                                num +=1
                                y = "FileChanges"+str(num)+".csv"
                                z = "RegistryChanges"+str(num)+".csv"
                            ans = str(input("Would you like to filter by Process Name? (y/n):"))
                            num = 0
                            if ans == 'y':
                                processname = str(input("Enter a process name:"))
                                for filename in os.listdir("."):
                                    if filename in pmltocsvlist:
                                        with open(".\\"+filename)as r:
                                            pmlreader = csv.reader(r)
                                            pmllines = list(pmlreader)
                                            for i in pmllines:
                                                if i[1] != processname and num != 0:
                                                    pmllines.remove(i)
                                                    num+=1
                                                else:
                                                    num+=1
                                                    pass
                                            writer = csv.writer(open(".\\Output\\"+filename,"w+",newline=""))
                                            writer.writerows(pmllines)
                                            num = 0
                                        del writer
                                        os.remove(".\\"+filename)
                                    else:
                                        pass
                        else:
                            os.system("FullEventLogView.exe /scomma \".\\Output\\"+specified+".csv\" /TimeFilter 0 /DataSource 3 /LogFolder \"C:\Windows\System32\winevt\Logs\" /LogFolderWildcard \""+specified+"\"")
                        ans = str(input("Do you want to extract another file(y/n):"))
                        if ans == 'y':
                            continue
                        else:
                            flag = False
                    else:
                        print("Invalid Location")
                        ans = str(input("Do you want to stop printing (y/n):"))
                        if ans == 'y':
                            flag = False
                        else:
                            continue
        else:
            pass

#RE-ENABLING THE LOGS IS SUPER IMPORTANT OR ELSE THE PROGRAM WILL NOT WORK AND U WILL NEED TO MANUALLY ENABLE ALL LOGS AGAIN!!!!
    print("Now the logs must be re-enabled.")
    for i in replacelist:
        print("Enter Y for the next Question")
        os.system("wevtutil.exe sl "+i+" /e:true")
    print("Event Logs analysis have been completed.")
