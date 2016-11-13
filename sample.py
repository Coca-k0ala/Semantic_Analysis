"""
This is an example script to parse mbox.files and detect phishing mails by using SEAHound program
You can also use this program to detect malicious dialogs.

"""

import read_mbox
import detect_urgency
import os

"""
we used phishing emails provided by Jose Nazario
reference:
Nazario, J. The online phishing corpus.https://monkey.org/~jose/phishing/, 2005. Accessed:2016-09-13.
"""
#you should put the path for your mbox file there
mbox_path = "D:/school/research/speech recognition/20051114.mbox"

#read mbox file and get list of mails
mails = read_mbox.get_mails_list(mbox_path)

#Given a list of all the mails, extract links from the file, using netcraft to perform link analysis, and
#then return list of remaining files which cannot be detected by the link analysis.
#set the save_files to True to save files that are not detected by link analysis to dir: link_failed
# remain_index = read_mbox.test_netcraft_all_mails(mails[66:], save_files=True)
# print(remain_index)

#this should be dir where you put files that you want to perform semantic analysis in. 
#The default path created is link_failed
# link_failed_path = os.getcwd()+"/link_failed/"
link_failed_path = os.getcwd()+"/no_link/" #change

#when you want to check a single file
# single_file = "1.txt"
# detect_urgency.check_mail_new_alg(link_failed_path + single_file)

#when you want to check all the files in a directory
# not_detected_list = detect_urgency.read_list_mails(link_failed_path)

#when you want to see the percentage of malicious mail detected by checking command and question
not_detected_list_QC, percent_QC = detect_urgency.percentage_detected(link_failed_path, only_QC=True)

#when you want to see the percentage of malicious mail detected by checking urgent tone and generic greeting.
not_detected_list, percent = detect_urgency.percentage_detected(link_failed_path, only_UG=True)

print("QC percentage")
print(not_detected_list_QC)
print(percent_QC)

print("UG percentage")
print(not_detected_list)
print(percent)