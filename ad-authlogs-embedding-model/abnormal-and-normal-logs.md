Exemple donné sur base d'un fichier de logs d’authentification (`/var/log/auth.log`): 
## **Entrées normales**  
Ces événements font partie du fonctionnement habituel d’un système :

1. **Connexion réussie d'un utilisateur légitime**  
   ```
   Feb 20 10:15:32 server sshd[12345]: Accepted password for user1 from 192.168.1.10 port 54321 ssh2
   ```
   - L’utilisateur `user1` s’est connecté via SSH avec succès.
   - L’IP source est une adresse locale (192.168.x.x), ce qui est souvent normal.

2. **Déconnexion propre d’un utilisateur**  
   ```
   Feb 20 10:30:12 server sshd[12345]: Received disconnect from 192.168.1.10 port 54321:11: Disconnected by user
   ```
   - L’utilisateur a fermé sa session volontairement.

3. **Exécution de commandes nécessitant des privilèges (via sudo)**  
   ```
   Feb 20 11:00:45 server sudo: user1 : TTY=pts/1 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/ls
   ```
   - L’utilisateur `user1` a exécuté `ls` avec sudo.

---

## **Entrées suspectes ou anormales**  
Ces événements peuvent indiquer une tentative d’intrusion ou une activité suspecte.

1. **Tentatives de connexion échouées répétées (bruteforce)**  
   ```
   Feb 20 12:05:22 server sshd[22345]: Failed password for invalid user admin from 203.0.113.45 port 44444 ssh2
   ```
   - Une tentative de connexion avec un utilisateur inexistant (`admin`).
   - L’IP source (203.0.113.45) peut être suspecte si elle est inconnue.

   ```
   Feb 20 12:05:23 server sshd[22346]: Failed password for root from 203.0.113.45 port 44445 ssh2
   ```
   - Tentative de connexion avec `root`, ce qui est un signe courant d’attaque par dictionnaire.

2. **Tentative de connexion avec un utilisateur désactivé ou bloqué**  
   ```
   Feb 20 12:10:30 server sshd[22350]: User nobody not allowed because account is locked
   ```
   - L’utilisateur `nobody` est bloqué, mais quelqu’un a tenté de l’utiliser.

3. **Accès root suspect (si inattendu)**  
   ```
   Feb 20 12:20:15 server sudo: unknownuser : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash
   ```
   - Un utilisateur inconnu tente d’obtenir des privilèges root.

4. **Modification suspecte des permissions ou des fichiers système**  
   ```
   Feb 20 12:45:33 server su: pam_unix(su:session): session opened for user root by hacker(uid=1001)
   ```
   - Un utilisateur non privilégié (`hacker`) a réussi à ouvrir une session root.

5. **Connexions à des heures inhabituelles ou depuis des adresses IP inconnues**  
   ```
   Feb 20 03:15:10 server sshd[30321]: Accepted password for user1 from 45.67.89.100 port 60000 ssh2
   ```
   - Si `user1` ne se connecte jamais à 3h du matin ni depuis cette IP, cela peut être suspect.

6. **Tentative d’élévation de privilèges sans succès**  
   ```
   Feb 20 13:00:00 server sudo: user2 : user NOT in sudoers ; TTY=pts/4 ; PWD=/home/user2 ; USER=root ; COMMAND=/bin/cat /etc/shadow
   ```
   - L’utilisateur `user2` tente de lire `/etc/shadow` sans avoir les droits.

---