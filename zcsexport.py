#!/usr/bin/env python3

from pythonzimbra.communication import Communication
from pythonzimbra.tools import auth
import os.path as path
import ssl, csv, os, pythonzimbra.communication, pythonzimbra.tools, configparser, argparse

# Gère la création du fichier texte qui stocke le jeton administrateur
def AdminTokenManagement(cache_admin_token_path, url_admin):
	if not os.path.exists(cache_admin_token_path): # Vérification de l'existence du fichier admin_token.txt
		open(cache_admin_token_path, "w").close() # Création de celui-ci s'il est inexistant
	else:
		with open(cache_admin_token_path, "r") as fichier: # Récupération du jeton administrateur dans le fichier admin_token.txt
			admin_token = fichier.read()
	comm = Communication(url_admin, context=context)
	request = comm.gen_request(token=admin_token)
	request.add_request(
	'NoOpRequest',
	{
	},
	'urn:zimbraAdmin'
	)
	no_op_response = comm.send_request(request) # Vérification de la validité du jeton administrateur via une requête vide
	if no_op_response.is_fault():
		if no_op_response.get_fault_code() == "service.AUTH_REQUIRED" or no_op_response.get_fault_code() == "service.AUTH_EXPIRED":
			admin_token = AuthenticationAndTokenWriter(url_admin, login_admin, psswrd_admin, context, cache_admin_token_path)
	return admin_token

# Authentification de l'utilisateur, génération du jeton et stockage de celui-ci dans un fichier texte
def AuthenticationAndTokenWriter(url_admin, login_admin, psswrd_admin, context, cache_admin_token_path): 
	admin_token = auth.authenticate(url_admin, login_admin, psswrd_admin, admin_auth=True, use_password=True, context=context)
	token_writer = open(cache_admin_token_path, "w")
	token_writer.write(admin_token)
	token_writer.close()
	return admin_token

# Permet de créer une requête qui sera envoyée en Langage Json au serveur Zimbra
def SearchDirectoryRequest(comm, admin_token, arg_query, arg_attrs): 
	request = comm.gen_request(token = admin_token)
	request.add_request(
    'SearchDirectoryRequest',
    {
        'query': arg_query, # Requête sur l'ensemble des comptes sauf les comptes système        
        'applyCos': 1,
        'attrs': arg_attrs
    },
    'urn:zimbraAdmin'
	)
	return comm.send_request(request)

# Recherche de l'attribut désiré pour les comptes e-mail et renvoie de sa valeur associée
def getAttribute(arr, search_pattern):
	value = []
	for account in arr:
		if account['n'] == search_pattern:
			value.append(account['_content'])
	return value

context = ssl._create_unverified_context() # Utilisation d'un protocole ssl pour communiquer de façon sécurisée avec le serveur web via internet

config = configparser.ConfigParser()
config.read ('config_zcsexport.ini')
url_admin  = config['CREDENCIALS']['url_admin'] # url (tirée du fichier config_zcsexport.ini) du serveur zimbra
login_admin  = config['CREDENCIALS']['login_admin'] # nom d'utilisateur (tirée du fichier config_zcsexport.ini) pour le serveur zimbra
psswrd_admin  = config['CREDENCIALS']['psswrd_admin'] # mot de passe (tirée du fichier config_zcsexport.ini) pour le serveur zimbra

comm = Communication(url_admin, context=context)

cache_admin_token_path = "admin_token.txt"
admin_token = AdminTokenManagement(cache_admin_token_path, url_admin)

# Accès aux arguments
parser = argparse.ArgumentParser()
   
parser.add_argument('-c', '--config', dest='configuration', action='store_true', help="Chemin du fichier de configuration des credentials Zimbra")
parser.add_argument('-o', '--output', dest='output', action='store_true', help="Chemin du fichier csv d'exportation")

parser.add_argument('--accounts', dest='accounts', action='store_true', help="Exporter les objets de type Account")
parser.add_argument('--dls', dest='dls', action='store_true', help="Exporter les objets de type Ditribution List")
parser.add_argument('--resources', dest='resources', action='store_true', help="Exporter les objets de type Resource")
parser.add_argument('--domains', dest='domains', action='store_true', help="Exporter les objets de type Domain")
parser.add_argument('--cos', dest='cos', action='store_true', help="Exporter les objets de type Class of Services")
parser.add_argument('--servers', dest='servers', action='store_true', help="Exporter les objets de type Server")

args = parser.parse_args()

if args.configuration:
	chemin_configuration = path.abspath("config_zcsexport.ini")
	print(chemin_configuration)
	exit (0)
if args.output:
	chemin_output = path.abspath("zcsexport.csv")
	print(chemin_output)
	exit(0)
if args.accounts:
	search_directory_response = SearchDirectoryRequest(comm, admin_token, '(&(mail=*)(!(zimbraIsSystemAccount=TRUE)))', 'zimbraMailAlias,zimbraMailQuota,zimbraAccountStatus')
else:
	print ('Veuillez entrer un argument (ou -h pour en avoir la liste)')
	exit (0)

soap_response = search_directory_response.get_response()['SearchDirectoryResponse']

# Céation du fichier zcsexport.csv contenant les données désirées par l'utilisateur
with open('zcsexport.csv', 'w', newline='') as csvfile:
    fieldnames = ['ID', 'Name', 'zimbraMailAlias', 'zimbraMailQuota', 'zimbraAccountStatus']
    zcs_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    zcs_writer.writeheader()
    for account in soap_response['account']:
    	row = {
		'ID': account['id'],
		'Name': account['name'],
		'zimbraMailAlias': '|'.join(getAttribute(account['a'], 'zimbraMailAlias')),
		'zimbraMailQuota': '|'.join(getAttribute(account['a'], 'zimbraMailQuota')),
		'zimbraAccountStatus': '|'.join(getAttribute(account['a'], 'zimbraAccountStatus'))
		}
    	zcs_writer.writerow(row)