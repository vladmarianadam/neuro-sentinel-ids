## Ce conține KDDTrain+.txt?

Este un fișier **CSV** (deși are extensia .txt) care conține **125,973 de înregistrări** de trafic de rețea, fiecare cu **41 de features** + 1 label (tipul de atac sau "normal").

## Structura fiecărei înregistrări

Fiecare linie reprezintă o **conexiune de rețea** cu următoarele caracteristici:

### Features (41 coloane):

**1. Basic features (9):**
```
1. duration - lungimea conexiunii în secunde
2. protocol_type - tcp, udp, icmp
3. service - http, ftp, smtp, etc. (70 de tipuri)
4. flag - status al conexiunii (SF, REJ, etc.)
5. src_bytes - bytes trimiși de la sursă
6. dst_bytes - bytes trimiși către destinație
7. land - 1 dacă sursă = destinație, 0 altfel
8. wrong_fragment - număr de fragmente greșite
9. urgent - număr de pachete urgente
```

**2. Content features (13):**
```
10. hot - număr de "hot" indicators
11. num_failed_logins - număr de login-uri eșuate
12. logged_in - 1 dacă logat cu succes
13. num_compromised - număr de condiții compromise
14. root_shell - 1 dacă s-a obținut root shell
15. su_attempted - 1 dacă s-a încercat su
16. num_root - număr de accese root
17. num_file_creations - fișiere create
18. num_shells - număr de shell prompts
19. num_access_files - operații pe fișiere de control
20. num_outbound_cmds - comenzi outbound
21. is_host_login - 1 dacă login de la host
22. is_guest_login - 1 dacă login de guest
```

**3. Time-based traffic features (9):**
```
23. count - număr de conexiuni la același host în ultimele 2 secunde
24. srv_count - conexiuni la același serviciu
25. serror_rate - % de conexiuni cu erori SYN
26. srv_serror_rate - % pentru același serviciu
27. rerror_rate - % cu erori REJ
28. srv_rerror_rate - % pentru același serviciu
29. same_srv_rate - % către același serviciu
30. diff_srv_rate - % către servicii diferite
31. srv_diff_host_rate - % către host-uri diferite
```

**4. Host-based traffic features (10):**
```
32-41. Similar cu 23-31 dar calculate pe ultimele 100 conexiuni
```

**42. Label** - tipul de trafic/atac

## Tipuri de Labels (23 clase)

### Normal:
- `normal` - trafic benign

### Atacuri (22 tipuri, grupate în 4 categorii):

**1. DoS (Denial of Service) - 7 tipuri:**
```
- back
- land
- neptune
- pod
- smurf
- teardrop
- apache2 (doar în test set)
- udpstorm (doar în test set)
- processtable (doar în test set)
- mailbomb (doar în test set)
```

**2. Probe (Scanning/Probing) - 4 tipuri:**
```
- ipsweep
- nmap
- portsweep
- satan
- mscan (doar în test set)
- saint (doar în test set)
```

**3. R2L (Remote to Local - acces neautorizat) - 8 tipuri:**
```
- ftp_write
- guess_passwd
- imap
- multihop
- phf
- spy
- warezclient
- warezmaster
- sendmail (doar în test set)
- named (doar în test set)
- snmpgetattack (doar în test set)
- snmpguess (doar în test set)
- xlock (doar în test set)
- xsnoop (doar în test set)
```

**4. U2R (User to Root - escaladare privilegii) - 4 tipuri:**
```
- buffer_overflow
- loadmodule
- perl
- rootkit
- sqlattack (doar în test set)
- xterm (doar în test set)
- ps (doar în test set)
```

## Exemplu de linie din fișier

```csv
0,tcp,http,SF,215,45076,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0.00,0.00,0.00,0.00,1.00,0.00,0.00,0,0,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,normal,21
```

Tradus:
- duration=0, protocol=tcp, service=http, flag=SF
- src_bytes=215, dst_bytes=45076
- ... alte features ...
- **Label: normal**
- **Difficulty level: 21** (ultima coloană - nivel de dificultate)

## Cum să îl folosești în Python

```python
import pandas as pd
import numpy as np

# Definește numele coloanelor
column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

# Încarcă datele
df = pd.read_csv('KDDTrain+.txt', names=column_names)

# Verifică structura
print("Shape:", df.shape)
print("\nPrimele 5 rânduri:")
print(df.head())

# Distribuția claselor
print("\nDistribuția atacurilor:")
print(df['label'].value_counts())

# Statistici
print("\nStatistici numerice:")
print(df.describe())
```

## Output așteptat:

```
Shape: (125973, 43)

Distribuția atacurilor:
normal          67343
neptune         41214
satan            3633
ipsweep          3599
portsweep        2931
smurf            2646
nmap             1493
back              956
teardrop          892
warezclient       890
pod               201
guess_passwd       53
buffer_overflow    30
warezmaster        20
land               18
imap               11
rootkit            10
loadmodule          9
ftp_write           8
multihop            7
phf                 4
perl                3
spy                 2
```

