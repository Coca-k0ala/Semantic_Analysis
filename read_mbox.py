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
import glob

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
		print("i: " + str(i))
		try:
			malicous = single_mail_malicious(mail)
		except:
			print("mail " + str(i)+ " error: ", sys.exc_info()[0])
			remain_list.append(i)
			if error_file:
				error_mails.write(str(i) + "\n")
			if save_files:
				# current_path = current_dir + "/mails/" + str(i) + ".txt"
				# new_path = current_dir + "/link_failed/" + str(i) + ".txt"
				#change
				current_path = current_dir + "/mails/" + str(i) + "_phishing2.txt"
				new_path = current_dir + "/link_failed/" + str(i) + "_phishing2.txt"
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
					# current_path = current_dir + "/mails/" + str(i) + ".txt"
					# new_path = current_dir + "/link_failed/" + str(i) + ".txt"
					#change
					current_path = current_dir + "/mails/" + str(i) + "_phishing2.txt"
					new_path = current_dir + "/link_failed/" + str(i) + "_phishing2.txt"
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
	"""
	create mails with metadata and content
	"""
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


def create_one(mails, write_file):
	"""create one big file of mails"""
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



def test_netcraft_all_indexs(index_list, mail):
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
	"""test area"""
	# test_single_mail(mails[381])
	# remove_error_mails()

	# print(single_mail_malicious(mails[95]))
	# error_mails = [1022]
	# test_netcraft_all_indexs(error_mails, mails)
	# test_netcraft_all_mails(mails)
	# test_netcraft_enron_all()
	# create_mails(mails)
	# create_full_mails(mails)

	"""test netcraft"""
	# url = "ia.topit.me/a/58/12/1145389728ef41258al.jpg"
	# url = "http://ia.topit.me"
	# input_URL_netcraft(url)

	#test enron with netcraft
	# enron_mail_path = "D:/school/research/speech recognition/enron_mail/140.txt"
	# enron_netcraft_singlemail(enron_mail_path)
	# #read all enron mails
	# test_netcraft_enron_all()