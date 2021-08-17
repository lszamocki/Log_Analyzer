import os.path
        
class LogAnalyzer():
    """ Parses and summarizes nginx logfiles """

    def __init__(self, readfile, writefile, topIP, topAction, topStatus, topActionIP, topStatusIP):
        """ Initializing """
        self.summary = {
            "actions": {},
            "ips": {},
            "statusCodes": {},
            "codeips": {},
            "actionips": {}
        }

        self.reafile = readfile
        self.writefile = writefile
        self.topIP = topIP
        self.topAction = topAction
        self.topStatus = topStatus
        self.topActionIP = topActionIP
        self.topStatusIP = topStatusIP
        

    def analyze(self):
        """ Reads and splits the access-log into our dictionary """
        #is file?
        if not os.path.isfile(self.reafile):
            print(self.reafile, "does not exist! exiting")
            exit(1)

        log = open(self.reafile, 'r')
        lines = log.readlines()
        log.close()
        loglist = []

        for s in lines:
            line = s.strip()
            tmp = line.split(' ')
            ip = tmp[0]

            #using double quotes to identify start and start places for lines in log file
            doublequotes = LogAnalyzer.find_chars(line, '"')

            #get the starting/ending indices of action & status code by their quotes
            action_start = doublequotes[0]+1
            action_end = doublequotes[1]
            statusCode_start = doublequotes[1]+2
            statusCode_end = doublequotes[1]+5
        

            #get both the status code + ip address and the HTTP action + ip address
            
            action = line[action_start:action_end]
            statusCode = line[statusCode_start:statusCode_end]
            codeip = statusCode + " " + ip
            actionip = action + " " + statusCode + " " + ip
            
            loglist.append({
                "ip": ip,
                "action": action,
                "statusCode": statusCode,
                "codeip": codeip,
                "actionip": actionip
            })

        self.summarize(loglist)
        self.write_summary()
    def summarize(self, cols):
        """ count occurences """
        for col in cols:
            if not col['action'] in self.summary['actions']:
                self.summary['actions'][col['action']] = 0
            self.summary['actions'][col['action']] += 1

            if not col['ip'] in self.summary['ips']:
                self.summary['ips'][col['ip']] = 0
            self.summary['ips'][col['ip']] += 1

            if not col['statusCode'] in self.summary['statusCodes']:
                self.summary['statusCodes'][col['statusCode']] = 0
            self.summary['statusCodes'][col['statusCode']] += 1

            if not col['codeip'] in self.summary['codeips']:
                self.summary['codeips'][col['codeip']] = 0
            self.summary['codeips'][col['codeip']] += 1

            if not col['actionip'] in self.summary['actionips']:
                self.summary['actionips'][col['actionip']] = 0
            self.summary['actionips'][col['actionip']] += 1

    def write_summary(self):
        """ sorts and writes occurences into file """
        summary = open(self.writefile, 'a')
        summary.write("Log summary: " + str(n) + "\n")
        
        iplist = sorted(self.summary['ips'].items(), key=lambda x: x[1], reverse=True)
        iplist = iplist[:self.topIP]
        summary.write("\nTop "+str(self.topIP)+' client IPs'+":\n")
        for l in iplist:
            summary.write(l[0]+": "+str(l[1])+" times\n")

        actionlist = sorted(self.summary['actions'].items(), key=lambda x: x[1], reverse=True)
        actionlist = actionlist[:self.topAction]
        summary.write("\nTop "+str(self.topAction)+' http actions'+":\n")
        for l in actionlist:
            summary.write(l[0]+": "+str(l[1])+" times\n")

        statuslist = sorted(self.summary['statusCodes'].items(), key=lambda x: x[1], reverse=True)
        statuslist = statuslist[:self.topStatus]
        summary.write("\nTop "+str(self.topStatus)+' http status codes'+":\n")
        for l in statuslist:
            summary.write(l[0]+": "+str(l[1])+" times\n")

        codeipslist = sorted(self.summary['codeips'].items(), key=lambda x: x[1], reverse=True)
        codeipslist = codeipslist[:self.topStatusIP]
        summary.write("\nTop "+str(self.topStatusIP)+' http status codes with their respective IP address'+":\n")
        for l in codeipslist:
            summary.write(l[0]+": "+str(l[1])+" times\n")

        actioniplist = sorted(self.summary['actionips'].items(), key=lambda x: x[1], reverse=True)
        actioniplist = actioniplist[:self.topActionIP]
        summary.write("\nTop "+str(self.topActionIP)+' http actions and status codes with their respective IP address'+":\n")
        for l in actioniplist:
            summary.write(l[0]+": "+str(l[1])+" times\n")    
        summary.write('\n')
        summary.close()

    @staticmethod
    def find_chars(string, char):
        """ returns a list of all indices of char inside string """
        return [i for i, ltr in enumerate(string) if ltr == char]
n = 1
print("Specify the top number of client IP's to look for: ")
clientIP = input()
print("Specify the top number of HTTP actions to look for: ")
httpAction = input()
print("Specify the top number of HTTP status codes to look for: ")
httpStatusCode = input()
print("Specify the top number of client IP's with a given http status code to look for: ")
ipstatus = input()
print("Specify the top number of client IP's with a given http action to look for: ")
ipaction = input()



for file in os.listdir('C:\\Users\\lszam\\Desktop\\log'):
    if __name__ == '__main__':
        logfile = 'C:\\Users\\lszam\\Desktop\\log\\access_' + str(n) + '.log'
        summaryfile = 'C:\\Users\\lszam\\Desktop\\summary.txt'
        summary = LogAnalyzer(logfile, summaryfile, int(clientIP), int(httpAction), int(httpStatusCode), int(ipstatus), int(ipaction))
        summary.analyze()
    n += 1     
print("done")