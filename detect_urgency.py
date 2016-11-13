"""This module is intended for people to input text content of emails, and output whether this email
is malicious or not."""

import re
import os
from nltk.corpus import wordnet as wn
from nltk.parse.stanford import StanfordDependencyParser
import shutil

verbs = {x.name().split('.', 1)[0] for x in wn.all_synsets('v')}
advs = {x.name().split('.', 1)[0] for x in wn.all_synsets('r')}
black_verb_list = ['enable', 'suspend', 'restrict', 'delete', 'limit', 'terminate', 'deactivate', 'lock', 'forfeit']
black_noun_list = ['theft', 'account', 'user', 'access', 'service', {'credit', 'card'}, 'registration', 'prize']
black_pair_list = [['strike', 'receive']]
black_compound_list = [{'account', 'suspension'}, {'account', 'block'}, {'account', 'closure'}, {'submit', 'account'}]
black_adv_verb_list = ['visit', 'click']
black_adv_noun_list = ['update']
black_adv_list = ['soon', 'urgent', 'must']
black_action_verb_list = ['click', 'enter', 'update', 'log', 'follow', 'visit', 'complete', 'sign', 
							'contact', 'read', 'send', 'paste','copy', 'insert', 'unlock', 'open',
							'email', 'login', 'access']
black_action_noun_list = ['link', 'password','account', 'information', 'system', 'verification', 
							'service', 'response', 'url', 'field', 'document', 'profile','browser',
							'record', 'cert']
black_command_verb_list = ['encourage', 'request', 'ask']

def dependency(sentence):
	"""
	input: a string 
	output: dependency Parse Tree
	Given a sentence, by using stanford dependency Parser, return its dependency tree
	"""
	dirname = os.path.split(os.path.abspath(__file__))[0]
	dep_parser = StanfordDependencyParser(path_to_jar=dirname, path_to_models_jar=dirname, model_path=dirname+'/englishPCFG.ser.gz')
	parse_tree = dep_parser.raw_parse(sentence)
	result = []
	for parse in parse_tree:
		result.append(list(parse.triples()))
	return result

def check_mail_three_condition(path):
	"""
	input: a string path
	output: True if this mail is malicious, False if not
	Given a file path, applying semantic analysis algorithm, and return whether it's malicious or not
	For this algorithm, there are three main condition: generic greeting, urgent tone, and malicious
	question/commnad. If any of these two condition is true, this algorithm classifies the file as malicious
	"""
	try:
		content = open(path, 'r').readlines()
	except:
		print("cannot find the file: " + path)
		return None
	check_urgent_flag = None
	check_action_flag = None
	score = 0
	if check_member(content[1:4]) or check_no_address(content[1:4]):
		score += 1

	for line in content:
		print repr(line)
		if not line.strip() == '':
			if not check_one_urgency(line): # there is bad consequency
				if check_urgent_flag != True:
					check_urgent_flag = True
					score += 1
					print("DETECTED BAD CONSEQUENCY TRUE")
			if check_command(line):
				print("is command")
				if not check_one_action(line):
					if check_action_flag != True:
						check_action_flag = True
						score += 1
						print("DETECTED BAD ACTION TRUE")
			subs = dectectSubclause(line)
			for sub in subs:
				if isQuestion(sub):
					print("is Question")
					if not check_one_action(line):
						if check_action_flag != True:
							check_action_flag = True
							score += 1
							print("DETECTED BAD ACTION TRUE")
			if score >= 2:  #true if both are true, which means this mail is malicious
				print("mail is malicious")
				return True
	return False #mail is legitimate

def check_mail_new_alg(path, only_QC=False, only_UG=False):
	"""
	input: a string path
	only_QC: only check malicious question and command mode.
	output: True if this mail is malicious, False if not
	Given a file path, applying semantic analysis algorithm, and return whether it's malicious or not
	This is our new algorithm, an email is detected as an attack if one of the following three conditions is met:
	Malicious link
	Malicious question/command
	Both Urgent tone and Generic greeting
	"""
	try:
		content = open(path, 'r').readlines()
	except:
		print("cannot find the file: " + path)
		return None
	if not only_QC:
		if check_member(content[1:4]) or check_no_address(content[1:4]):
			check_member_flag = True
			print("DETECTED XXXX MEMBER TRUE")
		else:
			check_member_flag = False

	for line in content:
		if not line.strip() == '':
			if not only_QC:
				if check_member_flag and not check_one_urgency(line): # there is bad consequency
					print("DETECTED GREETING AND URGENCE TRUE")
					print("MAIL IS MALICIOUS")
					return True
			if not only_UG:
				if check_command(line):
					# print("is command")
					if not check_one_action(line):
						print("DETECTED BAD ACTION TRUE")
						print("MAIL IS MALICIOUS")
						return True
				subs = dectectSubclause(line)
				for sub in subs:
					if isQuestion(sub):
						# print("is Question")
						if not check_one_action(line):
							print("DETECTED MALICIOUS QUESTION TRUE")
							print("MAIL IS MALICIOUS")
							return True
	return False #mail is legitimate

def percentage_detected(filedir, only_QC=False, only_UG=False):
	"""
	input: a string file directory
	only_QC: if only_QC equals to True, only check the percentage of malicious mails detected
	by malicious commands and questions.
	only_UG: if only_UG equals to True, only check the percentage of malicious mails detected
	by urgent tone and generic greeting.
	output: list of files that are not detected and its percentage
	Given a file path, applying semantic analysis algorithm, print the percentage of malicious mails detected
	by chosen method.
	"""
	filelist = [f for f in os.listdir(filedir) if os.path.isfile(filedir + f)][0:4] #change!
	no_pattern_list = list()
	error_list = list()
	malicious_list = list()
	# sorted_mails = sorted(filelist, key=lambda x: int(x[:-4]))
	for files in filelist:
		print(files)
		try:
			#use algorithm one
			# malicious = check_mail_three_condition(filedir+files)

			#use new semantic analysis algorithm
			if only_QC:
				malicious = check_mail_new_alg(filedir + files, only_QC=True)
			elif only_UG:
				malicious = check_mail_new_alg(filedir + files, only_UG=True)
			else:
				malicious = check_mail_new_alg(filedir + files)
		except:
			print("error in check mail for file: " + files)
			error_list.append(files)
			malicious = None

		if malicious is False: #file is legitimate
			no_pattern_list.append(files)
		if malicious is True:
			malicious_list.append(files)

	print("total mails: " + str(len(filelist)))
	print("error_list: " + str(error_list))
	print("size of no pattern list: " + str(len(no_pattern_list)))
	percent = float(len(malicious_list)) / len(filelist)
	print("detected percentage: " + str(percent*100) + "%")
	return no_pattern_list, percent

def read_list_mails(filedir):
	"""
	input: a string file directory
	output: list of files that are not detected
	Given a file path, applying semantic analysis algorithm, print the percentage of malicious mail detected
	"""
	filelist = [f for f in os.listdir(filedir) if os.path.isfile(filedir + f)]
	no_pattern_list = list()
	error_list = list()
	malicious_list = list()
	sorted_mails = sorted(filelist, key=lambda x: int(x[:-4]))
	for files in sorted_mails:
		print(files)
		try:
			#use algorithm one
			# malicious = check_mail_three_condition(filedir+files)

			#use new semantic analysis algorithm
			malicious = check_mail_new_alg(filedir + files)
		except:
			print("error in check mail for file: " + files)
			error_list.append(files)
			malicious = None

		if malicious is False: #file is legitimate
			no_pattern_list.append(files)
		if malicious is True:
			malicious_list.append(files)
	print("total mails: " + str(len(filelist)))
	# print("error_list: " + str(error_list))
	# print("size of no pattern list: " + str(len(no_pattern_list)))
	percent = float(len(malicious_list)) / len(filelist)
	print("detected percentage: " + str(percent*100) + "%")
	return no_pattern_list

def check_verb_inside(triple):
	if re.match('^V', triple[0][1]):
		return triple[0][0]
	if re.match('^V', triple[2][1]):
		return triple[2][0]

def check_noun_inside(triple):
	if re.match('^N', triple[0][1]):
		return triple[0][0]
	if re.match('^N', triple[2][1]):
		return triple[2][0]

def stem(word):
#stem verb to base tense
	from nltk.stem.wordnet import WordNetLemmatizer

	return WordNetLemmatizer().lemmatize(word, 'v')

def check_one_urgency(sentence):
#return true is sentence not contain bad consequency, false if not
	try:
		dependency_dict = dependency(sentence)
	except Exception, e:
		print("Cannot Generate dependency Tree. Error message: " + str(e))
		return True
	compound_list = list()
	verb_noun_list = list()
	for triple in dependency_dict[0]:
		# print(triple) #print tree
		if triple[1] == "nsubj" or triple[1] == "nsubjpass" or triple[1] == "dobj":
			verb_result = check_verb_inside(triple)
			noun_result = check_noun_inside(triple)
			if noun_result != None and verb_result != None:
				base_verb = stem(verb_result.lower())
				verb_noun_pair = [noun_result.lower(), base_verb]
				# print(verb_noun_pair)
				verb_noun_list.append(verb_noun_pair)
		if triple[1] == 'compound' or triple[1] == 'nmod':
			compound = {triple[0][0].lower(), triple[2][0].lower()}
			# print(compound)
			compound_list.append(compound)
			if compound in black_compound_list:
				# print("in black compound")
				return False
		if triple[1] == "advmod" or triple[1] == "aux":
			# print(triple)
			verb_result = triple[0][0].lower()
			base_verb = stem(verb_result)
			adv_result = triple[2][0].lower()
			if base_verb in black_adv_verb_list and adv_result in black_adv_list:
				# print("in black adv")
				return False #sentence contain urgency
		if triple[1] == "amod":
			#adv describe a noun
			# print(triple)
			noun_result = triple[0][0].lower()
			adv_result = triple[2][0].lower()
			base_noun = stem(noun_result)
			base_adv = stem(adv_result)
			if base_noun in black_adv_noun_list and base_adv in black_adv_list:
				# print("in black adv")
				return False #sentence contain urgency
			if base_noun in black_noun_list and base_adv in black_verb_list:
				# for sentence like "'Your account might be place on restricted status."
				return False

	for pair in verb_noun_list:
		if pair in black_pair_list:
			return False #contain bad consequence
		noun = pair[0]
		if pair[1] in black_verb_list:
			# print("in black verb")
			for compound in compound_list:
				if pair[0] in compound:
					noun = compound
			if noun in black_noun_list or pair[0] in black_noun_list:
				# print("in black noun")
				return False #sentence contain bad consequence
	return True

def check_one_action(sentence):
#return true is sentence not contain action, false if not
	#detect click here
	if (("click here" in sentence.lower()) or ("apply now" in sentence.lower()) 
		or ("confirm now" in sentence.lower())):
		return False #sentence contains click here
	# if re.match(r"\((.*)\)", sentence):
	# 	sentence = sentence
	urls = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+\~]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', sentence)
	if urls:
		return False #sentence contain link which imply request for action

	try:
		dependency_dict = dependency(sentence)
	except Exception, e:
		print("Cannot Generate dependency Tree. Error message: " + str(e))
		return True
	compound_list = list()
	verb_noun_list = list()
	for triple in dependency_dict[0]:
		# print(triple) #print tree
		if triple[1] == "nsubj" or triple[1] == "nsubjpass" or "dobj":
			verb_result = triple[0][0]
			noun_result = triple[2][0]
			base_verb = stem(verb_result.lower())
			noun_result = stem(noun_result.lower())
			verb_noun_pair = [noun_result.lower(), base_verb]
			# print(verb_noun_pair)
			verb_noun_list.append(verb_noun_pair)
		if triple[1] == 'compound' or triple[1] == 'nmod':
			if triple[0][0] == 'send' or triple[0][0] == 'response':
				obj = re.search(r'[\w\.-]+@[\w\.-]+', triple[2][0])
				if obj:
					return False #contain action require to send email
			compound = {triple[0][0].lower(), triple[2][0].lower()}
			# print(compound)
			compound_list.append(compound)
			if compound in black_compound_list:
				return False
		if triple[1] == 'dep':
			if triple[0][0] == 'email':
				obj = re.search(r'[\w\.-]+@[\w\.-]+', triple[2][0])
				if obj:
					return False #contain action require to send email

	# print(compound_list)
	for pair in verb_noun_list:
		noun = pair[0]
		if pair[1] in black_action_verb_list:
			for compound in compound_list:
				if pair[0] in compound:
					noun = compound
			# print(pair, noun)
			if noun in black_action_noun_list or pair[0] in black_action_noun_list:
				# print(pair)
				# print(noun)
				return False #sentence contain bad action
	return True


def check_member(sentences):
#return true if sentence contain XXX member, false is not
	# print(sentences)
	for sentence in sentences:
		# print(repr(sentence))
		obj = re.search(r'Dear(.*)(Member|member|client|user| Client|User|account|Account|customer|Customer|PayPal|Customers|Sir/Madam|Sir|Madam)(\s)?(,|:|\n|\s)', sentence)
		obj1 = re.search(r'^(Hello\,|Hi\,|Hi\!|Hello Again\:|Hi there\,)', sentence)
		if obj or obj1:
			# print obj1.group()
			return True
	return False

def check_no_address(sentences):
#check the first three sentences contain Hi, hello or dear, return false is there is one of them
	words = ['Hi', 'Hello', 'Dear']
	for sentence in sentences:
		if any(word in sentence for word in words):
			return False
	return True #There is no address

def check_command(sentence):
#return true if is command, false if not
	"""Check sentence starts with verb"""
	obj = re.match(r"\((.*)\)", sentence)
	if obj:
		sentence = (obj.group(1))
	# sentence = sentence.strip().lower()
	words = sentence.strip().lower().split()
	# words = nltk.word_tokenize(sentence)
	# pos = nltk.pos_tag(words)
	# if pos[0][0] in verbs:
	# 	print("wordnet verb")
	# 	return True
	# if re.match(r"^VB", pos[0][1]) or pos[0][0] in verbs: #start with verb
	# 	return True
	# print sentence
	if words[0] in verbs: #start with verb
		return True
	elif re.match(r'(^to|^In order to)', sentence, flags=re.IGNORECASE):
		return True
	# if re.match(r"(.*)?if (.*),", sentence):
	subsentences = sentence.split(",")
	# print("subsenteces: " + str(subsentences))
	# subsentences = dectectSubclause(sentence)
	# subsentences = subsentences + sentence.split(",")
	# print(subsentences)
	for subsentence in subsentences:
		words = subsentence.split()
		# print(subsentence)
		# print("words: " + str(words))
		if re.match(r"^please (.*)", subsentence) or re.match(r"(.*)?you (need|have) to (.*)", subsentence) or re.match(r"(.*)?you can (.*)", subsentence) or re.match(r"(.*) you should (.*)", subsentence):
			return True
		elif len(words) > 0 and words[0] in verbs:
			return True
	# print(sentence)
	if re.match(r"^please (.*)", sentence) or re.match(r"(.*)?you (need|have) to (.*)", sentence) or re.match(r"(.*)?you (can|could) (.*)", sentence) or re.match(r"(.*) you should (.*)", sentence):
		# print("in if .. please")
		return True
	if len(words) > 2 and words[0] in advs:
		if words[1] in verbs:
			# print("in advs")
			return True

	"""check common command pattern by dependency tree"""
	try:
		dependency_dict = dependency(sentence)
	except:
		print("Cannot Generate dependency Tree ")
		return False
	compound_list = list()
	verb_noun_list = list()
	for triple in dependency_dict[0]:
		# print(triple) #print tree
		if triple[1] == "dobj" or "nsubjpass":
			verb_result = triple[0][0]
			noun_result = triple[2][0]
			if noun_result.lower() == "you" or noun_result.lower() == "user":
				base_verb = stem(verb_result.lower())
				verb_noun_pair = [noun_result.lower(), base_verb]
				# print(verb_noun_pair)
				verb_noun_list.append(verb_noun_pair)
		if triple[1] == 'compound' or triple[1] == 'nmod':
			compound = {triple[0][0].lower(), triple[2][0].lower()}
			# print(compound)
			compound_list.append(compound)
	for pair in verb_noun_list:
		# noun = pair[0]
		if pair[1] in black_command_verb_list:
			# print("in here")
			return True #sentence is command
			# for compound in compound_list:
			# 	if pair[0] in compound:
			# 		noun = compound
			# if noun in black_action_noun_list or pair[0] in black_action_noun_list:
			# 	return False
	return False #sentence is not command

def normal_Parser(sentence):
	from nltk.parse.stanford import StanfordParser
	parser = StanfordParser(model_path='D:/school/CS175/amazon_project/englishPCFG.ser.gz')
	sentences = parser.raw_parse_sents([sentence])
	# print(sentences)
	for line in sentences:
		for sentence in line:
			print(type(sentence))

def dectectSubclause(sentence):
	"""return a list of subclauses"""
	from nltk.parse.stanford import StanfordParser
	parser = StanfordParser(model_path='D:/school/CS175/amazon_project/englishPCFG.ser.gz')
	try:
		sentences = parser.raw_parse_sents([sentence])
	except Exception, e:
		print("cannot generate parse tree for sentence: " + str(sentence))
		print(str(e))
		return []
	subs = list()
	for line in sentences:
		for sentence in line:
			# print(sentence)
			# print(sentence.productions())
			# print(sentence.flatten())
			for s in sentence.subtrees(lambda t: t.label() == "S"):
				# print(s.leaves())
				subsentece = " ".join(s.leaves())
				# print(subsentece)
				subs.append(subsentece)
	return subs

def isQuestion(sentence):
	"return true if a sentence's label is SQ"
	from nltk.parse.stanford import StanfordParser
	parser = StanfordParser(model_path='D:/school/CS175/amazon_project/englishPCFG.ser.gz')
	sentences = parser.raw_parse_sents([sentence])
	# print(sentences)
	for line in sentences:
		for sentence in line:
			# print(sentence)
			# print(sentence.label())
			for s in sentence.subtrees():
				if s.label() == "SINV" or s.label() == "SQ" or s.label() == "SBARQ":
					return True
	return False


if __name__ == '__Main__':

	"""test area"""
	# path = "D:/school/research/speech recognition/speech_to_text/SEParsernew/SEParser/testMails/urgency/428.txt"
	# path = "D:/school/research/speech recognition/speech_to_text/SEParsernew/SEParser/testMails/426.txt"
	# path = "D:/school/research/speech recognition/enron_mail/152.txt"
	# path = "D:/school/research/speech recognition/mails2/no_link5new2/no_action2/no_pattern/44.txt"
	# path = "D:/school/research/speech recognition/mails2/525.txt"
	# path = "D:/school/research/speech recognition/dialogs/3.txt"
	# path = "D:/school/research/speech recognition/mails/255.txt"
	path = "D:/school/research/speech recognition/578mail/553.txt"
	# print(check_mail(path))
	# print(check_mail_new_alg(path))
	filedir = "D:/school/research/speech recognition/578_result/no_link/"
	filedir = "D:/school/research/speech recognition/enron_mail_test/"
	# read_list_mails(filedir)

	# sentence = ["Dear eBay Member, Due to recent account takeovers and unauthorized listings, eBay is introducing a new account verification method."]
	# sentence = "Hi, hjkhk"
	# sentence = ["Dear PayPal , We recently noticed one or more attempts to log in to your PayPal accountfrom a foreign IP address."]
	# print(check_member(sentence))

	# i = "You have 3 days to enter required information or your credit card will be locked."
	# i = "However, if you did not initiatethe log ins, please visit PayPal as soon as possible to verify youridentity:https://www.paypal.com/us/cgi-bin/webscr?cmd=_login-run"
	# i = "Due to the suspension of this account, please be advised you are prohibited from using eBay in any way."
	# print(check_one_urgency(i))

	# s = "Please click here"
	# s = "To complete your PayPal Premier account, you must click the link below and enter your password on the following page to confirm your email address."
	# print(check_one_action(s))
	i = "And I think what happened was the new system that we are moving to the fields aren't compatible with the old system, so I've got some incomplete information for these people which I was tasked to call so do you have a couple of minutes so you can help me update your records?"
	# i = "do you have a couple of minutes so you can help me update your records?"
	i = "In order to update your account details please access the link below and complete the required steps: National Credit Union Association Security Update Once all the requirements are met, your account will be secured and safe from any possible future illegal use."
	i = "To take an advantages of current updrade you should login your account by using CitiBusiness Online application."
	i = "For update your Account click the link and follow the steps :- https://online.wellsfargo.com/signon?LOB=CONS "
	i = "To help speed up this process, please access the following link so we cancomplete the verification ofyour Chase Online Banking Account"
	i = "If this reached you by mistake please let us know by going here: http://vfq3.net/"
	i = "Confirm Now"
	i = "If you don't agree with this email and if you need assistance with your account, click here and process your login."
	# print(check_command(i))
	# print(check_one_action(i))

	"""test detect """
	# i = "do you have a couple of minutes"
	# print(isQuestion(i))
	i = "What is the password"
	# i = "Give me your password"
	# subs = dectectSubclause(i)
	# print(subs)
	# for sub in subs:
	# 	print(isQuestion(sub))
		# print(check_command(sub))
	# print(dependency(i))
	print(check_one_action(i))
	# i = "The security of the ATM PIN is very important."
	i = "Cloned and stolen card numbers are the point of vulnerability that enables identity theft."
	i = "ALERT: Third and FINAL Notification:"
	# print(check_one_urgency(i))#return true is sentence not contain bad consequency, false if not
	# print(normalParser(i))

	"""
	result:
	['203.txt', '22.txt', '224.txt', '225.txt', '24.txt', '247.txt', '255.txt', '257.txt', '258.txt', '26.txt', '268.txt', '271.txt', '273.txt', '279.txt', '282.txt', '374.txt', '56.txt', 'analysis.docx', 'analysis.txt', 'testMails.zip']
	['106.txt', '109.txt', '112.txt', '113.txt', '123.txt', '126.txt', '127.txt', '129.txt', '137.txt', '138.txt', 
	'14.txt',
	 '142.txt', '143.txt', '144.txt', '157.txt', '158.txt', '167.txt', '168.txt', 
	'17.txt', '200.txt', '219.txt', '235.txt', '252.txt', '261.txt', '277.txt', '285.txt', '303.txt', '312.txt', 
	'347.txt', '354.txt', 
	'360.txt', '367.txt', '380.txt', '389.txt', '393.txt', '407.txt', '416.txt', '417.txt', '428.txt']
	"""


	"""
	result:
	['101.txt', '105.txt', '106.txt', '11.txt', '110.txt', '116.txt', '13.txt', '131.txt', '132.txt', '135.txt', 
	'138.txt', '140.txt', '145.txt', '150.txt', '151.txt', '152.txt', '155.txt', '158.txt', '160.txt', '162.txt', 
	'163.txt', '165.txt', '166.txt', '171.txt', '174.txt', '175.txt', '183.txt', '184.txt', '191.txt', '198.txt',
	 '215.txt', '225.txt', '226.txt', '229.txt', '23.txt', '230.txt', '238.txt', '241.txt', '243.txt', '244.txt', 
	 '252.txt', '255.txt', '257.txt', '259.txt', '26.txt', '262.txt', '265.txt', '27.txt', '273.txt', '275.txt',
	  '276.txt', '277.txt', '281.txt', '290.txt', '291.txt', '295.txt', '3.txt', '303.txt', '304.txt', '305.txt',
	   '306.txt', '307.txt', '308.txt', '316.txt', '317.txt', '318.txt', '32.txt', '320.txt', '324.txt', '325.txt', 
	   '330.txt', '333.txt', '334.txt', '336.txt', '339.txt', '341.txt', '342.txt', '346.txt', '353.txt', '354.txt', 
	   '355.txt', '357.txt', '377.txt', '378.txt', '379.txt', '380.txt', '384.txt', '397.txt', '398.txt', '402.txt',
	    '403.txt', '404.txt', '406.txt', '407.txt', '418.txt', '421.txt', '424.txt', '428.txt', '433.txt', '434.txt', 
	    '439.txt', '446.txt', '447.txt', '458.txt', '461.txt', '462.txt', '463.txt', '465.txt', '467.txt', '469.txt', 
	    '471.txt', '482.txt', '486.txt', '487.txt', '488.txt', '495.txt', '5.txt', '501.txt', '58.txt', '59.txt',
	     '6.txt', '66.txt', '72.txt', '73.txt', '74.txt', '75.txt', '76.txt', '78.txt', '79.txt', '8.txt', '88.txt',
	      '91.txt', '95.txt', '96.txt']
	[]
	"""

	"""
	result:
	total mails: 500
	error_list: []
	no pattern list: 177
	['323.txt', '324.txt', '325.txt', '326.txt', '327.txt', '329.txt', '330.txt', '331.txt', '332.txt', '333.txt', '334.txt', '335.txt', '336.txt', '337.txt', '338.txt', '339.txt', '340.txt', '341.txt', '342.txt', '343.txt', '344.txt', '345.txt', '346.txt', '347.txt', '348.txt', '349.txt', '350.txt', '351.txt', '352.txt', '353.txt', '354.txt', '355.txt', '356.txt', '357.txt', '358.txt', '359.txt', '360.txt', '361.txt', '362.txt', '363.txt', '364.txt', '365.txt', '366.txt', '367.txt', '368.txt', '369.txt', '370.txt', '371.txt', '372.txt', '373.txt', '374.txt', '375.txt', '376.txt', '377.txt', '378.txt', '379.txt', '380.txt', '381.txt', '382.txt', '383.txt', '384.txt', '385.txt', '386.txt', '387.txt', '388.txt', '389.txt', '390.txt', '392.txt', '393.txt', '394.txt', '395.txt', '396.txt', '397.txt', '398.txt', '399.txt', '400.txt', '401.txt', '402.txt', '403.txt', '404.txt', '405.txt', '406.txt', '407.txt', '408.txt', '409.txt', '410.txt', '411.txt', '412.txt', '413.txt', '414.txt', '415.txt', '416.txt', '417.txt', '418.txt', '419.txt', '420.txt', '421.txt', '422.txt', '423.txt', '424.txt', '425.txt', '426.txt', '427.txt', '428.txt', '429.txt', '430.txt', '431.txt', '432.txt', '433.txt', '434.txt', '435.txt', '436.txt', '437.txt', '438.txt', '439.txt', '440.txt', '441.txt', '442.txt', '443.txt', '444.txt', '445.txt', '446.txt', '447.txt', '448.txt', '449.txt', '450.txt', '451.txt', '452.txt', '453.txt', '454.txt', '455.txt', '456.txt', '457.txt', '458.txt', '459.txt', '460.txt', '461.txt', '462.txt', '463.txt', '464.txt', '465.txt', '466.txt', '467.txt', '468.txt', '469.txt', '470.txt', '471.txt', '472.txt', '473.txt', '474.txt', '475.txt', '476.txt', '477.txt', '478.txt', '479.txt', '480.txt', '481.txt', '482.txt', '483.txt', '484.txt', '485.txt', '486.txt', '487.txt', '488.txt', '489.txt', '490.txt', '491.txt', '492.txt', '493.txt', '494.txt', '495.txt', '496.txt', '497.txt', '498.txt', '499.txt', '500.txt', '501.txt']
	detected percentage: 0

	"""
