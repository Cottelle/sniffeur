# README

- Nom de l'éxecutable: analyseur.
- ./analyseur -h pour l'aide.
- ./analyseur -i \<interface\> pour une execution classique.

## Présentation

Ce projet est un analyseur résaux. Il utilise la librairie libPCAP.  
Il tourne dans le terminal.  
Il implémente les protocoles suivants :  

- Ethernet  
- Ip Ipv6 (ARP est desactivé)  
- UDP TCP  
- bootp dhcp dns(en partie) http imap pop3 smtp telnet ftp  

Chaque protocole est dans son propore .h et .c il est inclus pas les protocoles plus bas (ethernet inclus udp qui lui inclus bootp).  

Il y a 3 niveaux de verbosité -v (1 = low | 2 = medium | 3 = high).  

