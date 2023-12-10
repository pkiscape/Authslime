#!/usr/bin/env python3


#=====================================================
#
# Authslime 
# A Cryptographic Slime with fun attributes
#=====================================================
#
#
#@version	1
#@link		https://github.com/pkiscape
#@authors	pkiscape.com

import argparse
import random
import string
import uuid
import json
import x50slime, slimedb, slimeimgcreator, slimestats
import timeit

def main():

	'''
	Main function using argparse for a CLI
	'''
	argparse_main = argparse.ArgumentParser(description="Authslime CLI tool")
	argparse_main.add_argument("-n","--number",type=int, help="Define how many authslime you would like to create",required=True)
	argparse_main.add_argument("-g","--graph", action="store_true", help="Pass this if you would like to view a graph",required=False)
	argparse_main.add_argument("-v","--verbose", action="store_true", help="Print authslime information and creation times",required=False)
	argparse_main.add_argument("-r","--rare", action="store_true", help="Rare Detector: prints information when a rare occurance happens",required=False)
	argparse_main.add_argument("-i","--images", action="store_true", help="Prints the authslime image in the img/ directory",required=False)
	args = argparse_main.parse_args()

	graph = args.graph if args.graph is not None else False
	verbose = args.verbose if args.verbose is not None else False
	rare = args.rare if args.rare is not None else False
	images = args.images if args.images is not None else False

	createauthslime(loop_number=args.number, graph=graph, verbose=verbose, rare=rare, images=images)

def getuid():
	uid = uuid.uuid4()
	return uid

def slimeversion():
	#Static for each version
	version = 1
	return version

def slimename():

	vowels = "a","e","i","o","u"
	
	#firstname
	fn_rand_num = random.randint(0,9)
	fn_firstletter = random.choice(string.ascii_uppercase)
	fn_secondletter = random.choice(vowels)
	fn_rest = ''.join(random.choices(string.ascii_lowercase, k = fn_rand_num))    
	fn = fn_firstletter + fn_secondletter + fn_rest	
	
	#lastname
	ln_rand_num = random.randint(0,10)
	ln_firstletter = random.choice(string.ascii_uppercase)
	ln_secondletter = random.choice(vowels)
	ln_rest = ''.join(random.choices(string.ascii_lowercase, k = ln_rand_num))
	ln = ln_firstletter + ln_secondletter + ln_rest
	fullname = fn + " " + ln
	return fullname

def slimecolor():
	#Chooses a color code
	r = lambda: random.randint(0,255)
	hexadecimal = '#%02X%02X%02X' % (r(),r(),r())
	return(hexadecimal)
	
def slimetemplate():
	#Chooses a template which will point to a png file
	template = random.randint(1,3)
	return template

def slimeaccessories():

	'''
	Slime will have two slots for accessories:

	Hat slot
	Other slot

	There will be two random rolls, one for each accessory. Ex. If common is chosen, it chooses a random common. 
	'''
	#Common
	common_other = ["sunglasses"]
	common_hat = ["sunhat"]
	
	#Uncommon
	uncommon_other = ["mustache"]
	uncommon_hat = ["top hat", "wizard hat"]

	#Rare
	rare_other = ["golden sunglasses"]
	rare_hat = ["robin hood hat", "santa hat", "crown", "golden top hat"]

	chosen = []

	#Other slot roll
	roll_other = random.randint(1,26)

	if roll_other in (1,2,3,4,5):
		chosen.append(random.choice(common_other))
		
	if roll_other in (9,10,11):
		chosen.append(random.choice(uncommon_other))
 
	if roll_other == 25:
		chosen.append(random.choice(rare_other))

	#Hat slot roll
	roll_hat = random.randint(1,26)

	if roll_hat in (1,2,3,4,5):
		chosen.append(random.choice(common_hat))

	if roll_hat in (9,10,11):
		chosen.append(random.choice(uncommon_hat))

	if roll_hat == 25:
		chosen.append(random.choice(rare_hat))

	return chosen

def createauthslime(loop_number,graph,verbose,rare,images):
	'''
	Creates an Authslime:
	1) Creates Attributes of the Slime (ID, KeyID, Version, Name, Color, Template, and Accessories)
	2) Crypto actions (Create keypair, CSR, Issues Certificate, KeyWrapping)
	3) Creates Slime Picture, containing Attributes
	4) Inserts data(Slime attributes/certs/keys/picture) into Database
	5) Optional actions such as read actions / stats and graphs
	'''

	total_rt = timeit.default_timer()

	#Create DB and Tables if not already created
	found = slimedb.check_tables()

	if found == False:
		slimedb.create_tables()

	loop_count = range(loop_number)
	slime_time_list = []
	for slime in loop_count:

		slime_start = timeit.default_timer()
		#-----------Create Attributes of the Slime-----------#
		slimeid = getuid()
		keyid = getuid()
		version = slimeversion()
		name = slimename()
		color = slimecolor()
		template = slimetemplate()
		accessories = slimeaccessories() 

		#-----------X509 Actions - Create keypair, CSR, IssueCertificate-----------#

		#Create Keypair
		#List will contain: [PrivateKey, PublicKey, wrappedsymkey, iv, aad, encryptor.tag, wrappedprivatekey]
		keys_table_list = x50slime.createkeypair(slimeid)
		
		privkey = keys_table_list[0] #Decrypted private key
		s_publickey = keys_table_list[1] # Serialized public key
		wrappedsymkey = keys_table_list[2]
		iv = keys_table_list[3]
		aad = keys_table_list[4]
		tag = keys_table_list[5]
		wrappedprivatekey = keys_table_list[6]
		publickey_digest = keys_table_list[7]

		#CSR
		_name = name.replace(" ", "_")
		commonname = _name +"_"+color+"_"+str(version)
		csr = x50slime.createslimecsr(privkey,commonname,slimeid)
		
		#X509 Certificate
		x50slime_list = x50slime.issueslimecert(csr,slimeid)
		slime_signature = x50slime_list[1]

		#-----------Create Slime Picture-----------#
		
		in_memory_authslime_image = slimeimgcreator.drawslime(slimeid,version,name,color,template,
			accessories,publickey_digest,images)

		#-----------Insert data into Database-----------#
		# Store Slime, Key and Accessories in DB
	
		slime_dict = (str(slimeid),str(keyid),version,name,color,template,in_memory_authslime_image)
		key_dict = (str(keyid),wrappedprivatekey,s_publickey, x50slime_list[0],wrappedsymkey,iv,aad,tag)
				
		slimedb.insert_into_slime_table(slime_dict)
		slimedb.insert_into_keys_table(key_dict)

		accessory_dict = {}

		for accessory in accessories:
			accessory_dict = (str(slimeid),accessory)
			slimedb.insert_into_accessories_table(accessory_dict)

		#End timer for individual Slime creation
		slime_time = timeit.default_timer() - slime_start
		slime_time_list.append(slime_time)
		if verbose:
			print(f"Slime Created: ID:{slime_dict[0]}, Name: {slime_dict[3]} in {slime_time} seconds")

		if rare:
			slime_list = slime_dict[0:6]
			rare_list = slimestats.slime_rare_detector(slime_list, accessories)

	#DB Read Actions
	#slimedb.read_all_slime()
	#slimedb.read_keys()

	#End timer for total create time
	create_time = timeit.default_timer() - total_rt
	if verbose:
		print("All Slime Creation Time: ", create_time)

	if graph:
		#-----------Graphs/Stats-----------#
		slimestats.slime_creation_graph(create_time, loop_number, slime_time_list)
	

if __name__ == '__main__':
	main()
