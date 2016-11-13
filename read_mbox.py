import mailbox
from bs4 import BeautifulSoup, SoupStrainer
import nltk.data
import re
import string
import time
import shutil
import os
import base64
import sys
import requests

def get_mails_list(mbox_path):
	"""
	input: mbox files
	output: list of mails
	Given a mbox file, return a list of mails that other functions can process
	"""
	mbox = mailbox.mbox(mbox_path)
	return [i for i in mbox]

def input_URL_netcraft(url, threshold=3):
	"""
	input: a url string, risk threshold
	output: return true if this url is malicious, false other wise

	Given a url and a risk threshold, use netcraft to detect whether this link is malicious or not 
	"""
	url = "http://toolbar.netcraft.com/site_report?url=" + url
	r = requests.get(url)
	data = r.text
	soup = BeautifulSoup(data, "lxml")
	risk = soup.find("span", class_="risk_label")
	risk = risk.get('data-risk')
	if int(risk) >= threshold:
		return True
	return False

def test_netcraft_all_mails(mails, error_file=False, save_files=False):
	"""
	input: list of mails from mbox file
	error_file: if error_file equals to True, write mails that have errors to a file into the project directory
	save_files: if save_files equals to True, save remaining files into the current project directory
	output: list of index of files that are not detected by netcraft

	Given a list of all the mails, extract links from the file, using netcraft to perform link analysis, and
	then return list of remaining files which cannot be detected by link analysis.
	"""
	if error_file:
		error_mails = open("error.txt", "w")
	if save_files:
		current_dir = os.getcwd()
		if not os.path.exists(current_dir + "/link_failed/"):
			os.mkdir(current_dir + "/link_failed/")
	malicous = None
	count = 0
	remain_list = list()
	wrong_list = list()
	for i, mail in enumerate(mails):
		i = i + 66 #change!
		print("i: " + str(i))
		try:
			malicous = single_mail_malicious(mail)
		except:
			print("mail " + str(i)+ " error: ", sys.exc_info()[0])
			remain_list.append(i)
			if error_file:
				error_mails.write(str(i) + "\n")
			if save_files:
				current_path = current_dir + "/mails/" + str(i) + ".txt"
				new_path = current_dir + "/link_failed/" + str(i) + ".txt"
				try:
					shutil.copy2(current_path, new_path)
				except:
					print("cannot move this file: " + str(i))
					remain_list.remove(i)
					wrong_list.append(i)
		else:    # when try succeed 
			if malicous != True:
				remain_list.append(i)
				if error_file and malicous == None:
					error_mails.write(str(i) + "\n")
				if save_files:
					current_path = current_dir + "/mails/" + str(i) + ".txt"
					new_path = current_dir + "/link_failed/" + str(i) + ".txt"
					try:
						shutil.copy2(current_path, new_path)
					except:
						print("cannot move this file: " + str(i))
						remain_list.remove(i)
						wrong_list.append(i)
			else:
				count += 1
	total_mail_number = len(mails)-len(wrong_list)
	print("total mail: " + str(total_mail_number))
	print("malicious count: " + str(count))
	print("number of remain mails: " + str(len(remain_list)))
	print("percentage detected by netcraft: " + str((float(count)/total_mail_number)*100) + "%")
	return remain_list

def split_sentence(text):
	tokenizer = nltk.data.load('tokenizers/punkt/english.pickle')
	content = '\n'.join(tokenizer.tokenize(text))
	# print(content)
	return content

def test_single_mail(message):
	mail_file = open("D:/school/research/speech recognition/" +"test.txt", "w")
	body = None
	links_list = list()
	if message.is_multipart():
		print('in if')
		for part in message.walk():
			if part.is_multipart():
				print('in sub if')
				for subpart in part.walk():
					if subpart.get_content_type() == 'text/html':
						body = subpart
					elif subpart.get_content_type() == 'text/plain':
						body = subpart
					else:
						print(subpart.get_content_type())
			elif part.get_content_type() == 'text/html':
				body = part
			elif part.get_content_type() == 'text/plain':
				body = part
			else:
				print(part.get_content_type())

	elif message.get_content_type() == 'text/html':
		print("in elif")
		body = message
	elif message.get_content_type() == 'text/plain':
		body = message
	else:
		print(message.get_content_type())

	if (body.get_payload() == None):
		mail_file.write("None" + '\n')
	elif body.get_content_type() == 'text/html':
		tmp = body.get_payload()
		enc = body['Content-Transfer-Encoding'].lower()
		if enc == "base64":
			tmp = base64.decodestring(tmp)
			print(tmp)
		print("start parsing")
		soup = BeautifulSoup(tmp,"html.parser")
		content = soup.get_text()
		content = content.encode('gbk', 'ignore')
		content = content.decode('gbk')
		content = content.replace('\n', ' ')
		content = content.replace('= ', '')
		content = content.encode('utf-8')
		tmp = []
		for l in content.split():
			tmp.append(l.strip())
		tmp = ' '.join(tmp)
	elif body.get_content_type() == 'text/plain':
		tmp = body.get_payload()
		enc = body['Content-Transfer-Encoding'].lower()
		if enc == "base64":
			tmp = base64.decodestring(tmp)
			# print(tmp)
		# enc = tmp['Content-Transfer-Encoding']
		# print('enc: ' + str(enc))
	else:
		print(body.get_content_type())
	# print(tmp)
	try:
		splited = split_sentence(tmp)
	except:
		splited_list = re.split(r"(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s", tmp)
		splited = ""
		for stuff in splited_list:
			splited += stuff + "\n"
		print(splited)
	mail_file.write(splited)

def search_url(line):
	return re.search(r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'\"\.\,\<\>\?]))', line)


def extractUrl(text, match):
	pretld, posttld = None, None
	url = ""

	tld = match[1]
	startpt, endpt = match[0][0], match[0][1]

	# check the next character is valid
	if len(text) > endpt:
		nextcharacter = text[endpt]
		if re.match("[a-z0-9-.]", nextcharacter):
			return None

		posttld = re.match(':?[0-9]*[/[!#$&-;=?a-z]+]?', text[endpt:])
	pretld = re.search('[a-z0-9-.]+?$', text[:startpt])

	if pretld:
		url = pretld.group(0)
		startpt -= len(pretld.group(0))
	url += tld
	if posttld:
		url += posttld.group(0)		
		endpt += len(posttld.group(0))

	# if it ends with a . or , strip it because it's probably unintentional
	url = url.rstrip(",.") 

	return (startpt, endpt), url

def parseText(text):
	results = []
	tlds = (tldextract.TLDExtract()._get_tld_extractor().tlds)
	tldindex = esm.Index()
	for tld in tlds:
		tldindex.enter("." + tld.encode("idna"))
	tldindex.fix()
	tldsfound = tldindex.query(text)
	results = [extractUrl(text, tld) for tld in tldsfound]
	results = [x for x in results if x] # remove nulls
	return results

def single_mail_malicious(message):
	"""
	input: a single mail
	output: true if the mail contains malicious link, false other wise, None when the mail has a wrong format
	
	Given give a single mail, perform link analysis, and check whether it contains malicious link or not
	"""
	body = None
	links_list = list()
	if message.is_multipart():
		for part in message.walk():
			if part.is_multipart():
				for subpart in part.walk():
					if 'text/html' in subpart.get_content_type():
						body = subpart
					elif subpart.get_content_type() == 'text/plain':
						body = subpart
					else:
						print(subpart.get_content_type())
			elif 'text/html' in part.get_content_type():
				body = part
			elif part.get_content_type() == 'text/plain':
				body = part
			else:
				print("problem: " + part.get_content_type())

	elif 'text/html' in message.get_content_type():
		body = message
	elif message.get_content_type() == 'text/plain':
		body = message
	else:
		print(message.get_content_type())

	if (body == None or body.get_payload() == None):
		print("no body")
	elif 'text/html' in body.get_content_type() or body.get_content_type() == "text/plain":
		new_content = ""
		for sentence in body.get_payload().split("\n"):
			if sentence.endswith('='):
				new_content += sentence[0:-1]
			else:
				new_content += sentence + "\n"

		"""using regex to find links"""
		new_content = string.replace(new_content, '<', ' ')
		new_content = string.replace(new_content, '=2e', '.')
		new_content = string.replace(new_content, '=2E', '.')
		urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+\~]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', new_content)
		for url in urls:
			print(url)
			if input_URL_netcraft(url):
				return True
			time.sleep(1)
		return False

		"""using beatifulsoup to find links"""
		# for link in BeautifulSoup(new_content, "html.parser", parse_only = SoupStrainer('a')):
		# 	if link.has_attr('href'):
		# 		print repr(link['href'])
		# 		# links_list.append(link['href'][2:])
		# 		obj = re.search(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",link['href'])
		# 		if obj:
		# 			# print("in search")
		# 			# print(obj.group())
		# 			link_new = obj.group()
		# 		else:
		# 			print('cannot extract link')
		# 			raise
		# 		# if link['href'].startswith('http://'):
		# 		# 	link_new = link['href'].split('http://', 1)[-1]
		# 		# elif link['href'].startswith('3D'):
		# 		# 	link_new = link['href'][2:]
		# 		# 	# print repr(link_new)
		# 		# 	if link_new.startswith('http://') or link_new.startswith('"http://'):
		# 		# 		link_new = link_new.split('http://', 1)[-1]
		# 		# 	elif link_new.startswith('https://') or link_new.startswith('"https://'):
		# 		# 		link_new = link_new.split('https://', 1)[-1]
		# 		# 	else:
		# 		# 		print("in link wrong: " + link_new)
		# 		# elif link['href'].startswith('https://'):
		# 		# 	link_new = link['href'].split('https://', 1)[-1]
		# 		# else:
		# 		# 	link_new = link['href'].split('http://', 1)[-1]
		# 		# 	if link_new.endswith("\""):
		# 		# 		link_new = link['href'].split('http://', 1)[-1][:-1]
		# 		print(link_new)
		# 		if input_URL_netcraft(link_new):
		# 			return True
		# return False

	else:
		print("mail type wrong: " + str(body.get_content_type()))
	return None

def create_full_mails(mails):
#create mails with metadata and content
	for i, message in enumerate(mails):
		mail_file = open("D:/school/research/speech recognition/mails2_full/" + str(i) +".txt", "w")
		mail_file.write(str(i)+'\n')
		body = message.read()
		# body = message.get_payload(decode = True)
		print(body)
		# mail_file.write(body)
		break


def create_mails(mails):
	for i, message in enumerate(mails):
		# UID = message.get('ID')
		# print("UID" + UID)
		mail_file = open("D:/school/research/speech recognition/mails2/" + str(i) +".txt", "w")
		mail_file.write(str(i)+'\n')
		body = None
		print(i)
		if message.is_multipart():
			# print('in if')
			for part in message.walk():
				if part.is_multipart():
					# print('in sub if')
					for subpart in part.walk():
						if subpart.get_content_type() == 'text/html':
							body = subpart
						elif subpart.get_content_type() == 'text/plain':
							body = subpart
						else:
							print(subpart.get_content_type())
				elif part.get_content_type() == 'text/html':
					body = part
				elif part.get_content_type() == 'text/plain':
					body = part
				else:
					print(part.get_content_type())

		elif message.get_content_type() == 'text/html':
			# print("in elif")
			body = message
		elif message.get_content_type() == 'text/plain':
			body = message
		else:
			print(message.get_content_type())

		if (body == None or body.get_payload == None):
			mail_file.write("None" + '\n')
			none_file_set.add(i)
		elif body.get_content_type() == 'text/html':
			print("start parsing")
			soup = BeautifulSoup(body.get_payload(),"html.parser")
			# print(soup.prettify())
			content = soup.get_text()
			content = content.encode('gbk', 'ignore')
			content = content.decode('gbk')
			content = content.replace('\n', ' ')
			content = content.replace('= ', '')
			tmp = []
			for l in content.split():
				tmp.append(l.strip())
			tmp = ' '.join(tmp)
		elif body.get_content_type() == 'text/plain':
			tmp = body.get_payload()
		else:
			print(body.get_content_type())
		try:
			splited = split_sentence(tmp)
		except:
			import re
			enders = re.compile('[.!?]')
			sentencelist = enders.split(tmp)
			splited = '\n'.join(sentencelist)
			print(splited)

		try:
			mail_file.write(splited)
		except:
			error_file_set.add(i)
	print(str(sorted(none_file_set)))
	print(str(sorted(error_file_set)))

"""
result:
[]
[66, 86, 108, 111, 117, 124, 147, 175, 217, 254, 265, 286, 301, 314, 316, 320, 321, 323, 329, 364, 373, 390, 436]
"""

def create_one(mails, write_file):
#create one big file of mails"
	for l in range(len(mails)):
		# file1 = open("D:/school/research/speech recognition/mail" + str(l) +".txt", "w")
		write_file.write(str(l)+'\n')
		message = mails[l]
		body = None
		# print(message)
		if message.is_multipart():
			print('in if')
			for part in message.walk():
				if part.is_multipart():
					print('in sub if')
					for subpart in part.walk():
						if subpart.get_content_type() == 'text/html':
							body = subpart.get_payload()
						else:
							print(subpart.get_content_type())
				elif part.get_content_type() == 'text/html':
					body = part.get_payload()
		elif message.get_content_type() == 'text/html':
			print("in elif")
			body = message.get_payload()
		if (body == None):
			file1.write("None" + '\n')
			continue
		soup = BeautifulSoup(body,"html.parser")
		# print(soup.prettify())
		content = soup.get_text()
		content = content.encode('gbk', 'ignore')
		content = content.decode('gbk')
		content = content.replace('\n', ' ')
		content = content.replace('= ', '')
		tmp = []
		for i in content.split():
			tmp.append(i.strip())
		tmp = ' '.join(tmp)
		result = ""
		for i in tmp:
			result += i
			if (i == "." or i == "?" or i == "!"):
				result += "\n"

		for i in result.split("\n"):
			file1.write(i.strip()+'\n')


# url = "ia.topit.me/a/58/12/1145389728ef41258al.jpg"
# url = "http://ia.topit.me"
# input_URL_netcraft(url)


def test_netcraft_all_indexs(index_list, mail):
	import sys
	import shutil
	error_mails = open("D:/school/research/speech recognition/mails2/no_link5new/error.txt", "w")
	for i in index_list:
		print(i)
		mail = mail[i]
		try:
			malicous = single_mail_malicious(mail)
		except:
			print("error: ", sys.exc_info()[0])
			error_mails.write(str(i))
			current_path = "D:/school/research/speech recognition/mails2/" + str(i) +".txt"
			new_path ="D:/school/research/speech recognition/mails2/no_link5/" + str(i) +".txt"
			shutil.copy2(current_path, new_path)
		else:    # when try succeed 
			if not malicous:
				if malicous == None:
					error_mails.write(str(i))
					current_path = "D:/school/research/speech recognition/mails2/" + str(i) +".txt"
					new_path ="D:/school/research/speech recognition/mails2/no_link5/" + str(i) +".txt"
					shutil.copy2(current_path, new_path)
				else:
					current_path = "D:/school/research/speech recognition/mails2/" + str(i) +".txt"
					new_path ="D:/school/research/speech recognition/mails2/no_link5/" + str(i) +".txt"
					shutil.copy2(current_path, new_path)


def enron_netcraft_singlemail(file_path):
	new_content = open(file_path, "r").read()
	# print(new_content)
	import re
	urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+\~]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', new_content)
	for link in urls:
		print(link)
		# if link.startswith('http://'):
		# 	link_new = link.split('http://', 1)[-1]
		# elif link.startswith('https://'):
		# 	link_new = link.split('https://', 1)[-1]
		# else:
		# 	link_new = link
		# 	print("wrong link: " + str(link))
		# print(link_new)
		if input_URL_netcraft(link):
			return True
	return False

def test_netcraft_enron_all():
	# from os import listdir
	# from os.path import isfile, join
	# for f in 
	import glob
	mails = glob.glob("D:\\school\\research\\speech recognition\\enron_mail\\*.txt")
	sorted_mails = sorted(mails, key = lambda x: int(x[49:-4]))
	# print(sorted_mails)
	# not_detect_mails = list()
	error_mails = list()
	for i, mail in enumerate(sorted_mails):
		print(mail)
		print(i+1)
		try:
			malicous = enron_netcraft_singlemail(mail)
		except:
			print("error: ", sys.exc_info()[0])
			error_mails.append(i+1)
			current_path = "D:/school/research/speech recognition/enron_mail/" + mail[49:-4] +".txt"
			new_path ="D:/school/research/speech recognition/enron_mail/error/" + mail[49:-4] +".txt"
			shutil.copy2(current_path, new_path)
		else:    # when try succeed 
			if not malicous:
				if malicous == None:
					error_mails.append(i+1)
					current_path = "D:/school/research/speech recognition/enron_mail/" + mail[49:-4] +".txt"
					new_path ="D:/school/research/speech recognition/enron_mail/error/" + mail[49:-4] +".txt"
					shutil.copy2(current_path, new_path)
			else:
				current_path = "D:/school/research/speech recognition/enron_mail/" + mail[49:-4] +".txt"
				new_path ="D:/school/research/speech recognition/enron_mail/detect/" + mail[49:-4] +".txt"
				shutil.copy2(current_path, new_path)
				print("detect: " + mail[49:-4])

	# print("not_detect_mails: ")
	# print(not_detect_mails)
	print("error_mails: ")
	print(error_mails)



def remove_error_mails():
	no_content_dir = "D:/school/research/speech recognition/mails_result/no_pattern/error/other language and no content/"
	no_content_filelist = [f for f in os.listdir(no_content_dir) if os.path.isfile(no_content_dir+ f)]
	print(no_content_filelist)
	# print(no_content_filelist)
	# other_l_dir = "D:/school/research/speech recognition/mails2/no_link5new2/no_action2/no_pattern2/other lanauge/"
	# print(other_l_dir)
	# other_l_filelist = [a for a in os.listdir(other_l_dir) if os.path.isfile(other_l_dir + a)]
	# other_l_filelist = []
	# for a in os.listdir(other_l_dir):
	# 	print(a)
	# 	if os.path.isfile(other_l_dir + a):
	# 		other_l_filelist.append(a)
	remain_dir = "D:/school/research/speech recognition/mails/"
	remain_filelist = [f for f in os.listdir(remain_dir) if os.path.isfile(remain_dir+ f)]
	# print(remain_filelist)
	for remain_f in remain_filelist:
		if remain_f in no_content_filelist:
			os.remove(remain_dir + remain_f)
			print(remain_f)




if __name__ == '__Main__':
	# mbox = mailbox.mbox("D:/school/research/speech recognition/phishing2.mbox")
	mbox = mailbox.mbox("D:/school/research/speech recognition/20051114.mbox")
	mails = [i for i in mbox]
	# file1 = open("D:/school/research/speech recognition/input.txt", "w")
	none_file_set =set()
	error_file_set = set()
	#test area
	# test_single_mail(mails[381])
	# remove_error_mails()

	# print(single_mail_malicious(mails[95]))
	# error_mails = [1022]
	# test_netcraft_all_indexs(error_mails, mails)
	# test_netcraft_all_mails(mails)
	test_netcraft_enron_all()
	# create_mails(mails)
	# create_full_mails(mails)
	"""
	result for mail2:
	[10, 12, 13, 14, 21, 34, 51, 326, 771, 1251, 1408, 1410, 1412, 1414]
	[29, 56, 65, 66, 164, 175, 251, 271, 364, 427, 640, 646, 666, 688, 754, 817, 823, 829, 944, 985, 1026, 1094, 1098, 1100, 1110, 1125, 1159, 1227, 1318, 1324, 1354, 1383, 1387]
	not_detect_mails:
	[1008, 1012, 1014, 1021, 1023, 1024, 1026, 1027, 1028, 1029, 1030, 1034, 1036, 1038, 1039, 1040, 1051, 1054, 1058, 1061, 1063, 1064, 1065, 1070, 1072, 1073, 1074, 1075, 1077, 1081, 1083, 1084, 1086, 1088, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1099, 1101, 1102, 1105, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1115, 1122, 1125, 1126, 1129, 1131, 1132, 1133, 1139, 1149, 1157, 1160, 1163, 1166, 1169, 1170, 1173, 1175, 1180, 1183, 1184, 1185, 1186, 1189, 1191, 1195, 1207, 1208, 1211, 1212, 1213, 1214, 1215, 1217, 1218, 1222, 1223, 1224, 1225, 1227, 1228, 1229, 1230, 1231, 1232, 1234, 1236, 1246, 1248, 1252, 1253, 1255, 1256, 1261, 1264, 1267, 1271, 1272, 1273, 1275, 1276, 1277, 1278, 1279, 1280, 1282, 1283, 1284, 1285, 1286, 1287, 1288, 1291, 1293, 1294, 1296, 1297, 1300, 1302, 1303, 1306, 1309, 1311, 1314, 1316, 1318, 1320, 1321, 1322, 1324, 1325, 1326, 1329, 1331, 1333, 1334, 1335, 1336, 1338, 1339, 1340, 1341, 1342, 1343, 1345, 1346, 1347, 1348, 1349, 1352, 1353, 1356, 1357, 1358, 1360, 1361, 1362, 1365, 1366, 1367, 1368, 1369, 1371, 1372, 1376, 1377, 1379, 1380, 1381, 1382, 1383, 1384, 1385, 1386, 1387, 1388, 1389, 1397, 1399, 1402, 1403, 1404, 1406, 1411, 1413, 1416, 1417, 1418, 1419, 1421, 1422]
	error_mails:
	[1022, 1076, 1103, 1104, 1106, 1123, 1127, 1142, 1147, 1148, 1161, 1177, 1179, 1182, 1193, 1206, 1251, 1268, 1307, 1308, 1315, 1319, 1323, 1327, 1328, 1330, 1332, 1337, 1350, 1355, 1359, 1363, 1364, 1370, 1373, 1374, 1375, 1378, 1390, 1401, 1408, 1410, 1412, 1414]
	"""


	"""
	result:
	not_detect_mails: 
	[1, 2, 3, 9, 13, 14, 15, 17, 18, 19, 24, 25, 26, 30, 33, 45, 46, 48, 49, 51, 56, 61, 63, 66, 67, 68, 69, 70, 71, 
	75, 86, 87, 93, 95, 96, 97, 98, 99, 100, 103, 106, 118, 122, 126, 127, 129, 132, 137, 138, 142, 143, 144, 146, 149,
	 150, 152, 154, 157, 158, 162, 163, 167, 168, 199, 200, 201, 203, 206, 210, 211, 216, 217, 219, 223, 224, 225, 228,
	  232, 234, 235, 237, 241, 242, 247, 248, 251, 254, 255, 258, 259, 260, 262, 264, 265, 268, 271, 272, 273, 277, 279, 
	  82, 283, 284, 285, 287, 288, 289, 290, 291, 299, 300, 301, 303, 306, 307, 309, 310, 311, 312, 314, 316, 319, 320, 
	  321, 323, 324, 326, 327, 328, 347, 354, 360, 363, 365, 367, 374, 381, 382, 389, 393, 394, 395, 397, 399, 400, 401,
	   407, 416, 417, 426, 427]
	error_mails: 
	[6, 7, 10, 22, 47, 50, 59, 65, 109, 112, 113, 123, 128, 133, 135, 139, 140, 141, 145, 147,
	 153, 156, 159, 164, 165, 179, 198, 202, 205, 213, 214, 215, 218, 220, 240, 252, 256, 257, 
	 261, 267, 304, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 380, 
	 390, 405, 406, 411, 419, 421, 422, 428]
	"""

	#test enron with netcraft
	# enron_mail_path = "D:/school/research/speech recognition/enron_mail/140.txt"
	# enron_netcraft_singlemail(enron_mail_path)
	# #read all enron mails
	# test_netcraft_enron_all()