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
    comm = Communication(url_admin, context = context)
    request = comm.gen_request(token = admin_token)
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

# Permet de créer une requête SearchDirectory qui sera envoyée en Langage Json au serveur Zimbra
def SearchDirectoryRequest(comm, admin_token, arg_query, arg_attrs, arg_types): 
    request = comm.gen_request(token = admin_token)
    request.add_request(
    'SearchDirectoryRequest',
    {
        'query': arg_query, # Requête sur l'ensemble des comptes sauf les comptes système        
        'applyCos': 1,
        'attrs': arg_attrs,
        'types': arg_types

    },
    'urn:zimbraAdmin'
    )
    return comm.send_request(request)

# Permet de créer une requête GetAllServer qui sera envoyée en Langage Json au serveur Zimbra
def GetAllServersRequest(comm, admin_token): 
    request = comm.gen_request(token = admin_token)
    request.add_request(
    'GetAllServersRequest',
    {
        
    },
    'urn:zimbraAdmin'
    )
    return comm.send_request(request)

# Recherche de l'attribut désiré pour les comptes e-mail et renvoie de sa valeur associée
def getAttribute(arr, search_pattern):
    value = []
    for i in arr:
        if i['n'] == search_pattern:
            value.append(i['_content'])
    return value

# Compte le nombre de fois où un attribut apparaît dans soap_response
def Attribute_counter(arr, search_pattern):
    compteur = 0
    for i in arr:
        if i['n'] == search_pattern:
            compteur = compteur + 1        
    return compteur

# Retourne True si un attribut existe dans soap_response
def Attribute_content_finder(arr, content): 
    for i in arr:
        if i['n'] == 'zimbraServiceEnabled':
            if(i['_content']) == content:
                return True
    return False

def getAccounts():
    search_directory_response = SearchDirectoryRequest(comm, admin_token, '(&(mail=*)(!(zimbraIsSystemAccount=TRUE)))', 'zimbraCreateTimestamp,'\
        'zimbraMailQuota,zimbraMailHost,zimbraMailTransport,zimbraCOSId,zimbraAccountStatus,zimbraFeatureMobileSyncEnabled,zimbraFeatureMAPIConnectorEnabled,'\
        'zimbraLastLogonTimestamp,zimbraPrefMailForwardingAddress,zimbraMailForwardingAddress', 'accounts')
    soap_response = search_directory_response.get_response()['SearchDirectoryResponse']
# Céation du fichier zcsexport.csv contenant les données désirées par l'utilisateur
    with open(chemin_output, 'w', newline = '') as csvfile:
        fieldnames = ['Name', 'zimbraId', 'zimbraCreateTimestamp', 'zimbraMailQuota', 'zimbraMailHost', 'zimbraMailTransport', 'zimbraCOSId', 'zimbraAccountStatus','\
        ' 'zimbraFeatureMobileSyncEnabled', 'zimbraFeatureMAPIConnectorEnabled', 'zimbraLastLogonTimestamp', 'Nbr_de_zimbraPrefMailForwardingAddress&zimbraMailForwardingAddress']
        zcs_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        zcs_writer.writeheader()
        for i in soap_response['account']:
            row = {
            'Name': i['name'],
            'zimbraId': i['id'],
            'zimbraCreateTimestamp': '|'.join(getAttribute(i['a'], 'zimbraCreateTimestamp')),
            'zimbraMailQuota': '|'.join(getAttribute(i['a'], 'zimbraMailQuota')),
            'zimbraMailHost': '|'.join(getAttribute(i['a'], 'zimbraMailHost')),
            'zimbraMailTransport': '|'.join(getAttribute(i['a'], 'zimbraMailTransport')),
            'zimbraCOSId': '|'.join(getAttribute(i['a'], 'zimbraCOSId')),
            'zimbraAccountStatus': '|'.join(getAttribute(i['a'], 'zimbraAccountStatus')),
            'zimbraFeatureMobileSyncEnabled': '|'.join(getAttribute(i['a'], 'zimbraFeatureMobileSyncEnabled')),
            'zimbraFeatureMAPIConnectorEnabled': '|'.join(getAttribute(i['a'], 'zimbraFeatureMAPIConnectorEnabled')),
            'zimbraLastLogonTimestamp': '|'.join(getAttribute(i['a'], 'zimbraLastLogonTimestamp')),
            'Nbr_de_zimbraPrefMailForwardingAddress&zimbraMailForwardingAddress': Attribute_counter(i['a'], 'zimbraPrefMailForwardingAddress') + Attribute_counter(i['a'], 'zimbraMailForwardingAddress')
            }
            zcs_writer.writerow(row)

def getDls():
    search_directory_response = SearchDirectoryRequest(comm, admin_token, '(&(objectClass=zimbraDistributionList))', 'zimbraMailStatus,zimbraMailForwardingAddress', 'distributionlists')
    soap_response = search_directory_response.get_response()['SearchDirectoryResponse']

    with open(chemin_output, 'w', newline = '') as csvfile:
        fieldnames = ['Name', 'zimbraMailStatus', 'nbr de membres(zimbraMailForwardingAddress)']
        zcs_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        zcs_writer.writeheader()
        for i in soap_response['dl']:
            row = {
            'Name': i['name'],
            'zimbraMailStatus': '|'.join(getAttribute(i['a'], 'zimbraMailStatus')),
            'nbr de membres(zimbraMailForwardingAddress)': Attribute_counter(i['a'], 'zimbraMailForwardingAddress')
            }
            zcs_writer.writerow(row)

def getResources():
    search_directory_response = SearchDirectoryRequest(comm, admin_token, '(&(objectClass=zimbraCalendarResource))', 'zimbraCreateTimestamp,zimbraCalResType,zimbraMailHost', 'resources')
    soap_response = search_directory_response.get_response()['SearchDirectoryResponse']

    with open(chemin_output, 'w', newline = '') as csvfile:
        fieldnames = ['Name', 'zimbraId', 'zimbraCreateTimestamp', 'zimbraCalResType','zimbraMailHost']
        zcs_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        zcs_writer.writeheader()
        for i in soap_response['calresource']:
            row = {
            'Name': i['name'],
            'zimbraId': i['id'],
            'zimbraCreateTimestamp': '|'.join(getAttribute(i['a'], 'zimbraCreateTimestamp')),
            'zimbraCalResType': '|'.join(getAttribute(i['a'], 'zimbraCalResType')),
            'zimbraMailHost': '|'.join(getAttribute(i['a'], 'zimbraMailHost'))
            }
            zcs_writer.writerow(row)

def getDomains():
    search_directory_response = SearchDirectoryRequest(comm, admin_token, '(&(objectClass=zimbraDomain))', 'zimbraCreateTimestamp,zimbraDomainStatus,zimbraDomainType,zimbraGalMode,'\
        'DKIMSelector,zimbraPreAuthKey,zimbraPublicServiceHostname,zimbraPublicServiceProtocol,zimbraVirtualHostname','domains')
    soap_response = search_directory_response.get_response()['SearchDirectoryResponse']

    with open(chemin_output, 'w', newline = '') as csvfile:
        fieldnames = ['Name', 'zimbraId', 'zimbraCreateTimestamp', 'zimbraDomainStatus', 'zimbraDomainType', 'zimbraGalMode', 'DKIMSelector', 'zimbraPreAuthKey','\
        ' 'zimbraPublicServiceHostname', 'zimbraPublicServiceProtocol', 'zimbraVirtualHostname']
        zcs_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        zcs_writer.writeheader()
        for i in soap_response['domain']:
            row = {
            'Name': i['name'],
            'zimbraId': i['id'],
            'zimbraCreateTimestamp': '|'.join(getAttribute(i['a'], 'zimbraCreateTimestamp')),
            'zimbraDomainStatus': '|'.join(getAttribute(i['a'], 'zimbraDomainStatus')),
            'zimbraDomainType': '|'.join(getAttribute(i['a'], 'zimbraDomainType')),
            'zimbraGalMode': '|'.join(getAttribute(i['a'], 'zimbraGalMode')),
            'DKIMSelector': '|'.join(getAttribute(i['a'], 'DKIMSelector')),
            'zimbraPreAuthKey': '|'.join(getAttribute(i['a'], 'zimbraPreAuthKey')),
            'zimbraPublicServiceHostname': '|'.join(getAttribute(i['a'], 'zimbraPublicServiceHostname')),
            'zimbraPublicServiceProtocol': '|'.join(getAttribute(i['a'], 'zimbraPublicServiceProtocol')),
            'zimbraVirtualHostname': '|'.join(getAttribute(i['a'], 'zimbraVirtualHostname'))
            }
            zcs_writer.writerow(row)

def getCos():
    search_directory_response = SearchDirectoryRequest(comm, admin_token, '(&(objectClass=zimbraCos))', 'zimbraMailQuota,zimbraCreateTimestamp', 'coses')
    soap_response = search_directory_response.get_response()['SearchDirectoryResponse']

    with open(chemin_output, 'w', newline = '') as csvfile:
        fieldnames = ['Name', 'zimbraId', 'zimbraMailQuota', 'zimbraCreateTimestamp']
        zcs_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        zcs_writer.writeheader()
        for i in soap_response['cos']:
            row = {
            'Name': i['name'],
            'zimbraId': i['id'],
            'zimbraMailQuota': '|'.join(getAttribute(i['a'], 'zimbraMailQuota')),
            'zimbraCreateTimestamp': '|'.join(getAttribute(i['a'], 'zimbraCreateTimestamp'))

            }
            zcs_writer.writerow(row)

def getServers():
    get_all_servers_response = GetAllServersRequest(comm, admin_token)
    soap_response = get_all_servers_response.get_response()['GetAllServersResponse']

    with open(chemin_output, 'w', newline = '') as csvfile:
        fieldnames = ['Name', 'zimbraId', 'zimbraCreateTimestamp', 'ldap', 'mta', 'proxy', 'mailbox', 'docs']
        zcs_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        zcs_writer.writeheader()
        for i in soap_response['server']:
            row = {
            'Name': i['name'],
            'zimbraId': i['id'],
            'zimbraCreateTimestamp': '|'.join(getAttribute(i['a'], 'zimbraCreateTimestamp')),
            'ldap': Attribute_content_finder(i['a'], 'ldap'),
            'mta': Attribute_content_finder(i['a'], 'mta'),
            'proxy': Attribute_content_finder(i['a'], 'proxy'),
            'mailbox': Attribute_content_finder(i['a'], 'mailbox'),
            'docs': Attribute_content_finder(i['a'], 'docs')

            }
            zcs_writer.writerow(row)

context = ssl._create_unverified_context() # Utilisation d'un protocole ssl pour communiquer de façon sécurisée avec le serveur web via internet

# Paramètres des arguments
parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', dest = 'configuration', type = str, default = os.path.join(os.getcwd(),'config_zcsexport.ini'), '\
    'help ="Permet de saisir le chemin du fichier de configuration des credentials Zimbra")
parser.add_argument('-o', '--output', dest = 'output', type = str, required = True, help = "Permet de saisir le chemin du fichier csv d'exportation")
parser.add_argument('--accounts', dest = 'accounts', action = 'store_true', help = "Exporter les objets de type Account")
parser.add_argument('--dls', dest = 'dls', action = 'store_true', help = "Exporter les objets de type Ditribution List")
parser.add_argument('--resources', dest = 'resources', action = 'store_true', help = "Exporter les objets de type Resource")
parser.add_argument('--domains', dest = 'domains', action = 'store_true', help = "Exporter les objets de type Domain")
parser.add_argument('--cos', dest = 'cos', action = 'store_true', help = "Exporter les objets de type Class of Services")
parser.add_argument('--servers', dest = 'servers', action = 'store_true', help = "Exporter les objets de type Server")

args = parser.parse_args()
if args.configuration:
    if not os.path.exists(args.configuration):
        print ("Le fichier config_zcsexport.ini n'existe pas au chemin indiqué ou dans le répertoire de travail courant, le programme va se fermer.")
        exit (0)
    else:
        chemin_configuration = args.configuration

if args.output:
    chemin_output = args.output

config = configparser.ConfigParser()
config.read (chemin_configuration)
url_admin  = config['CREDENCIALS']['url_admin'] # url (tirée du fichier config_zcsexport.ini) du serveur zimbra
login_admin  = config['CREDENCIALS']['login_admin'] # nom d'utilisateur (tirée du fichier config_zcsexport.ini) pour le serveur zimbra
psswrd_admin  = config['CREDENCIALS']['psswrd_admin'] # mot de passe (tirée du fichier config_zcsexport.ini) pour le serveur zimbra

comm = Communication(url_admin, context = context)

cache_admin_token_path = 'admin_token.txt'
admin_token = AdminTokenManagement(cache_admin_token_path, url_admin)

if args.accounts:
    getAccounts()
if args.dls:
    getDls()
if args.resources:
    getResources()
if args.domains:
    getDomains()
if args.cos:
    getCos()
if args.servers:
    getServers()