"""This module is intended for people to input text content of emails, and output whether this email
is malicious or not."""

import re
import os
from nltk.corpus import wordnet as wn
from nltk.parse.stanford import StanfordDependencyParser, StanfordParser
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

def normal_Parser(sentence):
	"""
	input: a string 
	output: print POS Parse Tree
	Given a sentence, by using stanford Parser, return its parse tree
	"""
	parser = StanfordParser(model_path='D:/school/CS175/amazon_project/englishPCFG.ser.gz')
	sentences = parser.raw_parse_sents([sentence])
	for line in sentences:
		for sentence in line:
			print(type(sentence))

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
		if len(line) < 200:
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
	filelist = [f for f in os.listdir(filedir) if os.path.isfile(filedir + f)]
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
	"""
	input: a string word
	output: a string word's original form
	Given a word, stem it to its base tense
	"""
	from nltk.stem.wordnet import WordNetLemmatizer
	return WordNetLemmatizer().lemmatize(word, 'v')

def check_one_urgency(sentence):
	"""
	input: a string sentence
	output: true if sentence does not contains urgency, false if sentence uses urgent tone
	Given a sentence, return true if sentence does not contains urgency, false if sentence uses urgent tone
	"""
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
				verb_noun_list.append(verb_noun_pair)
		if triple[1] == 'compound' or triple[1] == 'nmod':
			compound = {triple[0][0].lower(), triple[2][0].lower()}
			compound_list.append(compound)
			if compound in black_compound_list:
				return False
		if triple[1] == "advmod" or triple[1] == "aux":
			# print(triple)
			verb_result = triple[0][0].lower()
			base_verb = stem(verb_result)
			adv_result = triple[2][0].lower()
			if base_verb in black_adv_verb_list and adv_result in black_adv_list:
				return False #sentence contain urgency
		if triple[1] == "amod": #adv describe a noun
			noun_result = triple[0][0].lower()
			adv_result = triple[2][0].lower()
			base_noun = stem(noun_result)
			base_adv = stem(adv_result)
			if base_noun in black_adv_noun_list and base_adv in black_adv_list:
				return False #sentence contain urgency
			if base_noun in black_noun_list and base_adv in black_verb_list:
				# for sentence like "'Your account might be place on restricted status."
				return False

	for pair in verb_noun_list:
		if pair in black_pair_list:
			return False #contain bad consequence
		noun = pair[0]
		if pair[1] in black_verb_list:
			for compound in compound_list:
				if pair[0] in compound:
					noun = compound
			if noun in black_noun_list or pair[0] in black_noun_list:
				return False #sentence contain bad consequence
	return True

def check_one_action(sentence):
	"""
	input: a string sentence
	output: true if sentence does not contains malicious action, false other wise
	Given a sentence, return true if sentence does not contains malicious action, false other wise
	"""
	if (("click here" in sentence.lower()) or ("apply now" in sentence.lower()) 
		or ("confirm now" in sentence.lower())):
		return False #sentence contains click here
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
			verb_noun_list.append(verb_noun_pair)
		if triple[1] == 'compound' or triple[1] == 'nmod':
			if triple[0][0] == 'send' or triple[0][0] == 'response':
				obj = re.search(r'[\w\.-]+@[\w\.-]+', triple[2][0])
				if obj:
					return False #contain action require to send email
			compound = {triple[0][0].lower(), triple[2][0].lower()}
			compound_list.append(compound)
			if compound in black_compound_list:
				return False
		if triple[1] == 'dep':
			if triple[0][0] == 'email':
				obj = re.search(r'[\w\.-]+@[\w\.-]+', triple[2][0])
				if obj:
					return False #contain action require to send email

	for pair in verb_noun_list:
		noun = pair[0]
		if pair[1] in black_action_verb_list:
			for compound in compound_list:
				if pair[0] in compound:
					noun = compound
			if noun in black_action_noun_list or pair[0] in black_action_noun_list:
				return False #sentence contain bad action
	return True


def check_member(sentences):
	"""
	input: list of strings sentences
	output: true if the sentences contains generic greeting, false other wise
	Given a sentence, return true if the sentence contains generic greeting, false other wise
	"""
	for sentence in sentences:
		obj = re.search(r'Dear(.*)(Member|member|client|user| Client|User|account|Account|customer|Customer|PayPal|Customers|Sir/Madam|Sir|Madam)(\s)?(,|:|\n|\s)', sentence)
		obj1 = re.search(r'^(Hello\,|Hi\,|Hi\!|Hello Again\:|Hi there\,)', sentence)
		if obj or obj1:
			return True
	return False

def check_no_address(sentences):
	"""
	input: list of string sentences
	output: true if the sentences contains generic greeting, false other wise
	Given a sentence, return true if the sentence contains generic greeting, false other wise
	check the first three sentences contain Hi, hello or dear, return false is there is one of them
	"""
	words = ['Hi', 'Hello', 'Dear']
	for sentence in sentences:
		if any(word in sentence for word in words):
			return False
	return True #There is no address

def check_command(sentence):
	"""
	input: a string sentence
	output: true if sentence is a command, false other wise
	Given a sentence, return true if sentence is a command, false other wise
	"""

	"""Check sentence starts with verb"""
	obj = re.match(r"\((.*)\)", sentence)
	if obj:
		sentence = (obj.group(1))
	words = sentence.strip().lower().split()
	if words[0] in verbs: #start with verb
		return True
	elif re.match(r'(^to|^In order to)', sentence, flags=re.IGNORECASE):
		return True

	subsentences = sentence.split(",")
	for subsentence in subsentences:
		words = subsentence.split()
		if re.match(r"^please (.*)", subsentence) or re.match(r"(.*)?you (need|have) to (.*)", subsentence) or re.match(r"(.*)?you can (.*)", subsentence) or re.match(r"(.*) you should (.*)", subsentence):
			return True
		elif len(words) > 0 and words[0] in verbs:
			return True
	if re.match(r"^please (.*)", sentence) or re.match(r"(.*)?you (need|have) to (.*)", sentence) or re.match(r"(.*)?you (can|could) (.*)", sentence) or re.match(r"(.*) you should (.*)", sentence):
		return True
	if len(words) > 2 and words[0] in advs:
		if words[1] in verbs:
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
				verb_noun_list.append(verb_noun_pair)
		if triple[1] == 'compound' or triple[1] == 'nmod':
			compound = {triple[0][0].lower(), triple[2][0].lower()}
			compound_list.append(compound)
	for pair in verb_noun_list:
		if pair[1] in black_command_verb_list:
			return True #sentence is command
	return False #sentence is not command

def isQuestion(sentence):
	"""
	input: a string sentence
	output: true if sentence is a question, false other wise
	Given a sentence, return true if a sentence's label is SQ, false other wise
	"""
	parser = StanfordParser(model_path='D:/school/CS175/amazon_project/englishPCFG.ser.gz')
	sentences = parser.raw_parse_sents([sentence])
	for line in sentences:
		for sentence in line:
			for s in sentence.subtrees():
				if s.label() == "SINV" or s.label() == "SQ" or s.label() == "SBARQ":
					return True
	return False

def dectectSubclause(sentence):
	"""
	input: a string sentence
	output: eturn a list of subclauses
	Given a sentence, split it into list of subclauses
	"""
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
			for s in sentence.subtrees(lambda t: t.label() == "S"):
				subsentece = " ".join(s.leaves())
				subs.append(subsentece)
	return subs


if __name__ == '__Main__':

	"""test area"""
	path = "D:/school/research/speech recognition/578mail/553.txt"
	# print(check_mail(path))
	# print(check_mail_new_alg(path))
	filedir = "D:/school/research/speech recognition/enron_mail_test/"
	# read_list_mails(filedir)

	# sentence = ["Dear PayPal , We recently noticed one or more attempts to log in to your PayPal accountfrom a foreign IP address."]
	# print(check_member(sentence))

	# i = "Due to the suspension of this account, please be advised you are prohibited from using eBay in any way."
	# print(check_one_urgency(i))

	# s = "Please click here"
	# print(check_one_action(s))

	i = "If you don't agree with this email and if you need assistance with your account, click here and process your login."
	# print(check_command(i))
	# print(check_one_action(i))

	"""test detecting question"""
	# i = "do you have a couple of minutes"
	# print(isQuestion(i))
	i = "What is the password"
	# subs = dectectSubclause(i)
	# print(subs)
	# for sub in subs:
	# 	print(isQuestion(sub))
		# print(check_command(sub))
	# i = "The security of the ATM PIN is very important."
	# print(check_one_urgency(i))#return true is sentence not contain bad consequency, false if not
	# print(normalParser(i))
