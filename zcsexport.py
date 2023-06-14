#!/usr/bin/env python3

from pythonzimbra.communication import Communication
from pythonzimbra.tools import auth
import ssl, csv, os, pythonzimbra.communication, pythonzimbra.tools, configparser, time

def AdminTokenManagement(cache_admin_token_path, url_admin):
	if not os.path.exists(cache_admin_token_path):
		open(cache_admin_token_path, "w").close()
		admin_token = '0'
	else:
		with open(cache_admin_token_path, "r") as fichier:
			admin_token = fichier.read()
	comm = Communication(url_admin, context=context)
	request = comm.gen_request(token=admin_token)
	request.add_request(
	'NoOpRequest',
	{
	},
	'urn:zimbraAdmin'
	)
	no_op_response = comm.send_request(request)
	#print (no_op_response.get_response())
	if no_op_response.is_fault():
		if no_op_response.get_fault_code() == "service.AUTH_REQUIRED" or no_op_response.get_fault_code() == "service.AUTH_EXPIRED":
			admin_token = AuthenticationAndTokenWriter(url_admin, login_admin, psswrd_admin, context, cache_admin_token_path)
	return admin_token

def AuthenticationAndTokenWriter(url_admin, login_admin, psswrd_admin, context, cache_admin_token_path):
	admin_token = auth.authenticate(url_admin, login_admin, psswrd_admin, admin_auth=True, use_password=True, context=context)
	token_writer = open(cache_admin_token_path, "w")
	token_writer.write(admin_token)
	token_writer.close()
	return admin_token

def SearchDirectoryRequest(comm, admin_token):
	request = comm.gen_request(token = admin_token)
	request.add_request(
    'SearchDirectoryRequest',
    {
        'query': '(&(mail=*)(!(zimbraIsSystemAccount=TRUE)))', # Requête sur l'ensemble des comptes sauf les comptes système
        'applyCos': 1,
        'attrs': 'zimbraMailAlias,zimbraMailQuota,zimbraAccountStatus,zimbraCOSId'
    },
    'urn:zimbraAdmin'
	)
	
	return comm.send_request(request)

def getAttribute(arr, search_pattern):
	#toto = "tu recherches dans arr, le dic dont n==search_pattern, puis tu retourne la valeur de _content"
	#print (arr, search_pattern)
	value = None
	for account in arr:
		if account['n'] == search_pattern:
			value = account['_content']
			#print (value)
			
	return value

context = ssl._create_unverified_context()

config = configparser.ConfigParser()
config.read ('config_zcsexport.ini')
url_admin  = config['CREDENCIALS']['url_admin'] # url (tirée du fichier config_zcsexport.ini) vers le serveur zimbra
login_admin  = config['CREDENCIALS']['login_admin'] # nom d'utilisateur (tirée du fichier config_zcsexport.ini) pour le serveur zimbra
psswrd_admin  = config['CREDENCIALS']['psswrd_admin'] # mot de passe (tirée du fichier config_zcsexport.ini) pour le serveur zimbra

comm = Communication(url_admin, context=context)

cache_admin_token_path = "admin_token.txt"

admin_token = AdminTokenManagement(cache_admin_token_path, url_admin)
#print (admin_token)

search_directory_response = SearchDirectoryRequest(comm, admin_token)

soap_response = search_directory_response.get_response()['SearchDirectoryResponse']

# print(soap_response['account'])

with open('zcsexport.csv', 'w', newline='') as csvfile:
    fieldnames = ['ID', 'Name', 'zimbraMailAlias', 'zimbraMailQuota', 'zimbraAccountStatus']
    zcs_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    zcs_writer.writeheader()
    for account in soap_response['account']:
    	print (getAttribute(account['a'], 'zimbraMailAlias'))
    	row = {
		'ID': account['id'],
		'Name': account['name'],
		'zimbraMailAlias': getAttribute(account['a'], 'zimbraMailAlias'),
		'zimbraMailQuota': getAttribute(account['a'], 'zimbraMailQuota'),
		'zimbraAccountStatus': getAttribute(account['a'], 'zimbraAccountStatus')
		}
    	zcs_writer.writerow(row)