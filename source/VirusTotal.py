#! /usr/bin/env python3

import urllib2
import urllib
import postfile
import json
import os
import os.path
import hashlib
import fnmatch
import datetime
from optparse import OptionParser

apikey = None

def main():

    global apikey

    usage1 = "\n%prog --report -f <FILE> OR -d <DIRECTORY> AND -k <API-KEY>\n"
    usage2 =   "%prog --report --md5list <FILE> OR --md5 <SUM> AND -k <API-KEY>\n"
    usage3 =   "%prog --send -f <FILE> AND -k <API-KEY>\n"
    usage4 =   "%prog --send -d <DIRECTORY> AND --terminal[DEFAULT] OR --txt AND -k <API-KEY>\n"

    description = ( "Get reports from VirusTotal from a single MD5, list of MD5s, single file or all files within a directory.\n"
                    "Send files or all files with in a directory to VirusTotal for scanning.\n"
                    "Uses VirusTotal Public API v2.0"
                   )

    parser = OptionParser(usage1+usage2+usage3+usage4, version="%prog 1.0",description=description)


    parser.add_option("--report", action="store_const",dest="mode", const="report", help="MODE: Get report from already scanned file or checksum")
    parser.add_option("--send", action="store_const",dest="mode", const="send", help="MODE: Send file or entire directory to VirusTotal for scanning")

    parser.add_option("--terminal", action="store_const",dest="output", const="terminal", help="OUTPUT: to Terminal [default]")
    parser.add_option("--txt", action="store_const",dest="output", const="textfile", help="OUTPUT: to Textfile")

    parser.add_option("-f",dest="file", help="file to get report of or send")
    parser.add_option("-d",dest="directory", help="directory to get report of or send")

    parser.add_option("--md5list",dest="md5list", help="file with list of checksums")

    parser.add_option("--md5",dest="md5", help="a md5 checksum")

    parser.add_option("-k","--key", dest="key", help="your own apikey to access VirusTotal Public API. Leave out to use default/public key")

    parser.set_defaults(output="terminal")

    (options, args) = parser.parse_args()

    mode                = options.mode
    output              = options.output
    f                   = options.file
    directory           = options.directory
    md5list             = options.md5list
    md5                 = options.md5
    apikey              = options.key

    # If no api-key is inputed the public key will be used
    if not apikey:
        apikey = "1fe0ef5feca2f84eb450bc3617f839e317b2a686af4d651a9bada77a522201b0"

    #REPORT MODE
    if mode == "report":
        # GET REPORT OF A FILE
        if f:
            GetScanReportMD5(GetMD5(f))
        # GET REPORT OF A ENTIRE DIRECTORY
        elif directory:
            getDetectionRatePath(directory)
        # GET REPORT OF A LIST OF MD5 SUMS
        elif md5list:
            GetScanReportMD5FileList(md5list)
        # GET REPORT OF A MD5 SUM
        elif md5:
            GetScanReportMD5(md5)
    # SEND MODE
    elif mode == "send":
        # SEND A FILE
        if f:
            ScanFile(f)
        # SEND ENTIRE DIRECTORY
        else:
            if output == "terminal":
                ScanFilesOutput2terminal(directory)
            elif output == "textfile":
                ScanFilesOutput2textfile(directory)

    else:
        parser.print_help()

# Print text to a file
def PrintToFile(filename,text):
    try:
        foutput = open(filename,'a')
        foutput.write(text+"\n")
    except Exception, e:
        print "[-]    " + str(e) + "\n"
        return

#Returns the detection rate, if rate > 0 from an entire folder
def getDetectionRatePath(path):
        filelist = getAllFilesFromDir(path)
        for f in filelist:
            md5 = GetMD5(f)
            print f,",",md5,",",GetDetectionRateMD5(md5)


# Search path for files, returns a list of files
def getAllFilesFromDir(path):
    if os.path.exists(path):
        fileList = list()
        for file in os.listdir(path):
            if fnmatch.fnmatch(file, "*.*"):
                fileList.append(os.path.join(path,file))
        return fileList
    else:
        print("Directory does not exist!")



# Search path and subdirs for image files, returns a list of files
def getAllFilesFromDirSubDir(path):
    if os.path.exists(path):
        fileList = list()
        for path, subdirs, files in os.walk(path):
            for name in files:
                if fnmatch.fnmatch(name):
                    fileList.append(os.path.join(path, name))
        return fileList
    else:
        print("Directory does not exist!")



# Get MD5 of file
def GetMD5(fname):
    fh = open(fname, 'rb')
    m = hashlib.md5()
    while True:
        data = fh.read(8192)
        if not data:
            break
        m.update(data)
    return m.hexdigest()

# Report from md5 listed in a textfile
def GetScanReportMD5FileList(fname):
    try:
        f = open(fname)
    except Exception, e:
        print "[-]    " + str(e) + "\n"
        return

    for line in f:
        if not line.strip():
            continue
        else:
            result = GetDetectionRateMD5(line)
            if result:
                print line.strip(),",", result

    f.close()

# Get rate from single md5
def GetDetectionRateMD5(md5):
    try:
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": md5,"apikey": apikey}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        r = urllib2.urlopen(req)
        jsondata = r.read()
        jsondict = json.loads(jsondata)

        if jsondict['response_code'] == 0:
            print "[-]    ",jsondict['verbose_msg']
        else:
            return str(jsondict['positives'])+"/"+str(jsondict['total'])
    except Exception, e:
        if "204" in str(e):
            print "[-]    Exceed the public API request rate limit.\n"
            return
        else:
            print "[-]    " + str(e) + "\n"
            return

# Report from a single md5 sum from VirusTotal
def GetScanReportMD5(md5):
    try:
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": md5,"apikey": apikey}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        r = urllib2.urlopen(req)
        jsondata = r.read()
        jsondict = json.loads(jsondata)

        if jsondict['response_code'] == 0:
            print "[-]    ",jsondict['verbose_msg']
        else:
            print "-----------------------INFO------------------------------------"
            print "md5: " + jsondict['md5']
            print "sha1: " + jsondict['sha1']
            print "sha256: " + jsondict['sha256']
            print "Status: " + jsondict['verbose_msg']
            print "Scan date: " + jsondict['scan_date']
            print "Detection rate: ",jsondict['positives'],"/",jsondict['total']
            print "-----------------------SCANS-----------------------------------"
            for i in jsondict['scans']:
                print i,": ",jsondict['scans'][i]['result']
    except Exception, e:
        if "Forbidden" in str(e):
            print   "[-]    Forbidden access. Check your API-key.\n"
            return
        elif "204" in str(e):
            print "[-]    Exceed the public API request rate limit.\n"
            return
        else:
            print "[-]    " + str(e) + "\n"
            return


# Send a file to VirusTotal for scanning
def ScanFile(fname):
    try:
        host = "www.virustotal.com"
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", apikey)]
        file_to_send = open(fname, "rb").read()
        files = [("file", fname, file_to_send)]
        r = postfile.post_multipart(host, selector, fields, files)
        jsondict = json.loads(r)

        print "-----------------------INFO------------------------------------"
        print "File: " + os.path.abspath(fname)
        print "md5: " + jsondict['md5']
        print "Link: " + jsondict['permalink']
        print "Status: " + jsondict['verbose_msg']
    except Exception, e:
        if "204" in str(e):
            print "[-]    Exceed the public API request rate limit.\n"
            return
        else:
            print "[-]    " + str(e) + "\n"
            return

# Send multiple files to VirusTotal from a path and output to terminal
def ScanFilesOutput2terminal(path):
    try:
        host = "www.virustotal.com"
        fields = [("apikey", apikey)]
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        filelist = getAllFilesFromDir(path)
        for fname in filelist:
            file_to_send = open(fname, "rb").read()
            files = [("file", fname, file_to_send)]
            r = postfile.post_multipart(host, selector, fields, files)
            jsondict = json.loads(r)
            print "-----------------------INFO------------------------------------"
            print "File: " + os.path.abspath(fname)
            print "md5: " + jsondict['md5']
            print "Link: " + jsondict['permalink']
            print "Status: " + jsondict['verbose_msg']
    except Exception, e:
        if "204" in str(e):
            print "[-]    Exceed the public API request rate limit.\n"
            return
        else:
            print "[-]    " + str(e) + "\n"
            return
# Send multiple files to VirusTotal from a path and output to file
def ScanFilesOutput2textfile(path):
    try:
        host = "www.virustotal.com"
        fields = [("apikey", apikey)]
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"

        filename = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S_UploadedToVirusTotal")+".txt"
        foutput = open(filename,'a')

        filelist = getAllFilesFromDir(path)

        for fname in filelist:
            file_to_send = open(fname, "rb").read()

            files = [("file", fname, file_to_send)]
            r = postfile.post_multipart(host, selector, fields, files)
            jsondict = json.loads(r)

            foutput.write(os.path.abspath(fname)+","+jsondict['md5']+","+jsondict['permalink']+"\n")

            print os.path.abspath(fname) + "," + jsondict['verbose_msg']

        print "\n\n[+]    Detailes has been saved to        " + filename
    except Exception, e:
        if "204" in str(e):
            print "[-]    Exceed the public API request rate limit.\n"
            return
        else:
            print "[-]    " + str(e) + "\n"
            return

if __name__ == '__main__':
    main()
