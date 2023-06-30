# zcsexport

/*
* zcsexport.py permet l'export sous forme de fichier .csv d'informations depuis un serveur Zimbra selon des attributs
* Copyright (C) 2023  Développé pour Zextras Services (France) par Quentin LHOTE 🤖️

*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

******************************************************************************************************************************
L'utilisateur doit se connecter au serveur Zimbra en tant qu'administrateur.
Pour cela, le fichier config_zscexport.ini doit être constitué ainsi:

[CREDENCIALS]
url_admin = |url du serveur Zimbra|:|port|/service/admin/soap
login_admin = |identifiant administrateur|
psswrd_admin = |mot de passe administrateur|

******************************************************************************************************************************
Liste des arguments possibles:

usage: zcsexport.py [-h] [-c CONFIGURATION] [-o OUTPUT] [--accounts] [--dls] [--resources] [--domains] [--cos] [--servers]

options:
  -h, --help            show this help message and exit
  -c CONFIGURATION, --config CONFIGURATION
                        Permet de saisir le chemin du fichier de configuration des credentials Zimbra
  -o OUTPUT, --output OUTPUT
                        Permet de saisir le chemin du fichier csv d'exportation #!ARGUMENT OBLIGATOIRE!#
  --accounts            Exporter les objets de type Account
  --dls                 Exporter les objets de type Ditribution List
  --resources           Exporter les objets de type Resource
  --domains             Exporter les objets de type Domain
  --cos                 Exporter les objets de type Class of Services
  --servers             Exporter les objets de type Server
