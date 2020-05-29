#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import re


# In[ ]:


def extract(filename):
    with open(filename) as f:
        log = f.read()
        regexp2 = r"(?P<ip>.*?) (?P<remote_log_name>.*?) (?P<userid>.*?) \[(?P<date>.*?) (?P<timezone>.*?)\] \"(?P<request_method>.*?) (?P<path>.*?) (?P<request_version>.*?)\" (?P<status>.*?) (?P<length>.*?) \"(?P<referrer>.*?)\" \"(?P<user_agent>.*?)\""
        ips_list = re.findall(regexp2, log)
        return ips_list


# In[ ]:


#extract list
logs = extract('/var/log/httpd/access_log')


# In[ ]:


import numpy as np


# In[ ]:


#conver list to numpy array
log_arr = np.array(logs)


# In[ ]:


log_arr


# In[ ]:


#extract only the IP address
ips_list=log_arr[:,0]


# In[ ]:


import pandas as pd


# In[ ]:


dataset = pd.DataFrame({'IP': log_arr[:, 0], 'A': log_arr[:, 1],'B':log_arr[:, 2],'Date&Time':log_arr[:, 3],'TZ':log_arr[:, 4],'C':log_arr[:, 5],'Site':log_arr[:, 6],'Protocol':log_arr[:, 7],'Status_Code':log_arr[:, 8],'Length':log_arr[:, 9]})


# In[ ]:


dataset.head()


# In[ ]:


from collections import Counter


# In[ ]:


def counters(ips_list):
    count = Counter(ips_list) #will create a dictionary
    return count


# In[ ]:


import csv


# In[ ]:


def write_csv(counter):
    with open("output1.csv", "w") as csvfile:
        writer = csv.writer(csvfile)
        header = ['IP','Count']
        writer.writerow(header)
        for item in counter:
            writer.writerow((item,counter[item]))


# In[ ]:


write_csv(counters(ips_list))


# In[ ]:


freqdata = pd.read_csv('output1.csv')


# In[ ]:


freqdata.shape


# In[ ]:


freqdata.head()


# In[ ]:


import seaborn as sns


# In[ ]:


sns.scatterplot(freqdata['IP'],freqdata['Count'])


# ###  Produce Color list
# 

# In[ ]:


color=[]


# In[ ]:


for i in range(0,len(freqdata)):

    if freqdata['Count'][i] < 200:
        color.append(0)
    else:
        color.append(1)


# ###  IN CASE OF DOS ATTACK

# In[ ]:


sns.scatterplot(freqdata['IP'],freqdata['Count'],hue=color)


# In[ ]:


import os


# In[ ]:


datarray = np.array(freqdata)
IPLIST = []
Block = 0


# In[ ]:


for i in range(0,len(datarray)):
    if datarray[i][1] > 200:
        print("This ip is blocked {}".format(datarray[i][0]))
        IPLIST.append(datarray[i][0])
        #block the ip address
        os.system("firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address= {} reject'".format(datarray[i][0]))
        #generate a html analyzer using goaccess
        os.system("goaccess /etc/logs/httpd/access_log --log-format=COMBINED -a -o /var/www/html/report.html")
        Block =1 #variable used in sending mail


# ###  Send Mail of log analyzer when any ip is blocked

# In[ ]:



# libraries to be imported 
import smtplib 
from email.mime.multipart import MIMEMultipart 
from email.mime.text import MIMEText 
from email.mime.base import MIMEBase 
from email import encoders 

fromaddr = "hsdd@gmail.com"
toaddr = "sdif@gmail.com"

# instance of MIMEMultipart 
msg = MIMEMultipart() 

# storing the senders email address 
msg['From'] = fromaddr 

# storing the receivers email address 
msg['To'] = toaddr 

# storing the subject 
msg['Subject'] = "DOS Attack Blocked"

# string to store the body of the mail 
body = "IP has been Blocked"+str(IPLIST)

# attach the body with the msg instance 
msg.attach(MIMEText(body, 'plain')) 

# open the file to be sent 
filename = "report.html"
attachment = open("/var/www/html/report.html", "rb") 

# instance of MIMEBase and named as p 
p = MIMEBase('application', 'octet-stream') 

# To change the payload into encoded form 
p.set_payload((attachment).read()) 

# encode into base64 
encoders.encode_base64(p) 

p.add_header('Content-Disposition', "attachment; filename= %s" % filename) 

# attach the instance 'p' to instance 'msg' 
msg.attach(p) 

# creates SMTP session 
s = smtplib.SMTP('smtp.gmail.com', 587) 

# start TLS for security 
s.starttls() 

# Authentication 
s.login(fromaddr, "eqaksldk;f") 

# Converts the Multipart msg into a string 
text = msg.as_string() 

# sending the mail 
s.sendmail(fromaddr, toaddr, text) 

# terminating the session 
s.quit() 


# In[ ]:




