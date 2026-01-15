# 📘 Ghid Complet: Setup Mașini Virtuale ICS

## Ce ai disponibil

```
resourses/
├── VirtualBox-7.0.14-161095-Win.exe    (Installer)
├── ubuntu-24.04.3-live-server-amd64.iso (Ubuntu Server)
└── ICS-Attacker/                        (Kali VM pre-built)
    └── ICS-Attacker-1.16.vbox
```

---

# PARTEA 1: Instalare VirtualBox

## Pas 1.1: Instalează VirtualBox

1. Navighează la: `C:\Users\catalin.butacu\Downloads\ICS\resourses`
2. Dublu-click pe `VirtualBox-7.0.14-161095-Win.exe`
3. Click **Next** → **Next** → **Yes** (Network warning) → **Install**
4. Așteaptă instalarea → **Finish**

## Pas 1.2: Verifică instalarea

1. Deschide **Oracle VM VirtualBox Manager**
2. Ar trebui să vezi o fereastră goală cu lista de VMs

---

# PARTEA 2: Import VM Kali (Attacker)

## Pas 2.1: Importă VM-ul pre-existent

1. În VirtualBox: **Machine** → **Add...**
2. Navighează la: `resourses\ICS-Attacker\ICS-Attacker-1.16.vbox`
3. Click **Open**
4. VM-ul apare în listă ca "ICS-Attacker"

## Pas 2.2: Verifică setările

1. Click dreapta pe **ICS-Attacker** → **Settings**
2. **System** → RAM: minim 2048 MB
3. **Network** → Adapter 1:
   - ✅ Enable Network Adapter
   - Attached to: **Internal Network**
   - Name: `ics-lab`
4. Click **OK**

---

# PARTEA 3: Creare VM Ubuntu - Defense

## Pas 3.1: Crează VM nou

1. Click **New**
2. Completează:
   - Name: `ICS-Defense`
   - Folder: (lasă default)
   - Type: **Linux**
   - Version: **Ubuntu (64-bit)**
3. Click **Next**

## Pas 3.2: Hardware

1. Base Memory: **2048 MB**
2. Processors: **2 CPUs**
3. Click **Next**

## Pas 3.3: Hard Disk

1. Selectează **Create a Virtual Hard Disk Now**
2. Disk Size: **20 GB**
3. Click **Next** → **Finish**

## Pas 3.4: Atașează ISO

1. Click dreapta pe **ICS-Defense** → **Settings**
2. **Storage** → Click pe iconița CD goală (Empty)
3. Click pe iconița CD din dreapta → **Choose a disk file...**
4. Navighează la: `resourses\ubuntu-24.04.3-live-server-amd64.iso`
5. Click **Open** → **OK**

## Pas 3.5: Configurează Network

1. **Settings** → **Network**
2. **Adapter 1**:
   - ✅ Enable Network Adapter
   - Attached to: **Internal Network**
   - Name: `ics-lab`
3. **Adapter 2**:
   - ✅ Enable Network Adapter
   - Attached to: **NAT**
4. Click **OK**

---

# PARTEA 4: Instalare Ubuntu Server - Defense

## Pas 4.1: Pornește VM

1. Selectează **ICS-Defense**
2. Click **Start**

## Pas 4.2: Boot și Language

1. Așteaptă boot-ul (poate dura 1-2 minute)
2. Selectează **English** → **Enter**
3. **Continue without updating** → **Enter**

## Pas 4.3: Keyboard

1. Layout: **English (US)** sau **Romanian**
2. **Done** → **Enter**

## Pas 4.4: Network (IMPORTANT!)

1. Vei vedea 2 interfețe:
   - `enp0s3` - Internal Network (fără IP deocamdată)
   - `enp0s8` - NAT (va primi IP automat via DHCP)
2. Selectează `enp0s3` → **Edit IPv4**
3. Schimbă de la **Automatic (DHCP)** la **Manual**
4. Completează:
   ```
   Subnet: 10.0.0.0/24
   Address: 10.0.0.10
   Gateway: (lasă gol)
   Name servers: 8.8.8.8
   ```
5. **Save** → **Done**

## Pas 4.5: Proxy & Mirror

1. Proxy: (lasă gol) → **Done**
2. Mirror: (lasă default) → **Done**

## Pas 4.6: Storage

1. **Use an entire disk** → **Done**
2. Confirmă: **Done** → **Continue**

## Pas 4.7: Profile Setup

1. Your name: `ics-defense`
2. Your server's name: `ics-defense`
3. Username: `ics-defense`
4. Password: `ics2026`
5. **Done**

## Pas 4.8: SSH

1. ✅ **Install OpenSSH server**
2. **Done**

## Pas 4.9: Featured Snaps

1. Nu selecta nimic → **Done**
2. Așteaptă instalarea (5-10 minute)
3. Când vezi **Reboot Now** → **Enter**

## Pas 4.10: După reboot

1. Scoate ISO-ul:
   - În VirtualBox: **Devices** → **Optical Drives** → **Remove disk**
2. Apasă **Enter** să continue boot-ul
3. Login cu: `defense` / `defense123`

---

# PARTEA 5: Creare VM Ubuntu - Webapp

## Pas 5.1: Repetă pașii 3.1 - 3.3 cu:

- Name: `ICS-Webapp`
- RAM: **1024 MB**
- Disk: **10 GB**

## Pas 5.2: Network (doar Internal)

1. **Settings** → **Network**
2. **Adapter 1**:
   - Attached to: **Internal Network**
   - Name: `ics-lab`
3. **Adapter 2**: (dezactivat)

## Pas 5.3: Instalare Ubuntu

Repetă pașii 4.1 - 4.10 cu diferențele:

- **Network** (pas 4.4):
  ```
  Subnet: 10.0.0.0/24
  Address: 10.0.0.20
  Gateway: 10.0.0.10
  Name servers: 8.8.8.8
  ```
- **Profile** (pas 4.7):
  - name: `webapp`
  - server name: `ics-webapp`
  - username: `webapp`
  - password: `webapp123`

---

# PARTEA 6: Configurare Kali (Attacker)

## Pas 6.1: Pornește Kali

1. Selectează **ICS-Attacker** → **Start**
2. Login (credențialele standard Kali): `kali` / `kali`

## Pas 6.2: Configurează IP static

```bash
sudo nano /etc/network/interfaces
```

Adaugă/modifică:
```
auto eth0
iface eth0 inet static
    address 10.0.0.100
    netmask 255.255.255.0
    gateway 10.0.0.10
```

Salvează: **Ctrl+O** → **Enter** → **Ctrl+X**

```bash
sudo systemctl restart networking
```

## Pas 6.3: Verifică IP

```bash
ip addr show eth0
# Trebuie să vezi: 10.0.0.100
```

---

# PARTEA 7: Test Conectivitate

## Pas 7.1: De pe Kali (10.0.0.100)

```bash
# Ping Defense
ping 10.0.0.10 -c 3

# Ping Webapp
ping 10.0.0.20 -c 3
```

**Rezultat așteptat:** 3 packets transmitted, 3 received

## Pas 7.2: De pe Defense (10.0.0.10)

```bash
# Ping Attacker
ping 10.0.0.100 -c 3

# Ping Webapp
ping 10.0.0.20 -c 3
```

---

# PARTEA 8: Instalare Dependențe

## Pas 8.1: Pe ICS-Defense (10.0.0.10)

```bash
sudo apt update
sudo apt install python3 python3-pip git -y
pip3 install flask scikit-learn requests pandas numpy
```

## Pas 8.2: Pe ICS-Webapp (10.0.0.20)

```bash
sudo apt update
sudo apt install python3 python3-pip git -y
pip3 install flask scikit-learn requests
```

## Pas 8.3: Pe ICS-Attacker (Kali - 10.0.0.100)

```bash
sudo apt update
pip3 install requests
```

---

# PARTEA 9: Deploy Cod

## Pas 9.1: Opțiunea A - Git Clone

**Pe fiecare VM:**
```bash
git clone https://github.com/YOUR_REPO/ICS.git
cd ICS/src
```

## Pas 9.2: Opțiunea B - Transfer manual

**De pe Windows (PowerShell):**
```powershell
# Către Defense
scp -r C:\Users\catalin.butacu\Downloads\ICS\src defense@10.0.0.10:~/

# Către Webapp
scp -r C:\Users\catalin.butacu\Downloads\ICS\src webapp@10.0.0.20:~/

# Către Kali
scp -r C:\Users\catalin.butacu\Downloads\ICS\src kali@10.0.0.100:~/
```

---

# PARTEA 10: Rulare Sistem

## Terminal pe ICS-Defense:
```bash
cd ~/src/defensive
export ICS_ENV=production
python3 detector.py &

cd ~/src/firewall
python3 firewall.py &
```

## Terminal pe ICS-Webapp:
```bash
cd ~/src/webapp
export ICS_ENV=production
python3 webapp.py --case 3
```

## Terminal pe ICS-Attacker:
```bash
cd ~/src/offensive
export ICS_ENV=production
python3 demo_exploit.py
```

---

# Sumar IP-uri și Porturi

| VM | IP | Serviciu | Port |
|----|-----|----------|------|
| ICS-Attacker | 10.0.0.100 | attacker.py | - |
| ICS-Defense | 10.0.0.10 | detector.py | 5000 |
| ICS-Defense | 10.0.0.10 | firewall.py | 5001 |
| ICS-Webapp | 10.0.0.20 | webapp.py | 5002 |

---

# 🛠️ Depanare: VERR_FILE_NOT_FOUND

Dacă ai renumit folderul sau fișierele și VirtualBox caută calea veche (eroare `VERR_FILE_NOT_FOUND`):

1. Click dreapta pe VM → **Settings** → **Storage**.
2. Selectează controller-ul SATA.
3. Dacă vezi un disc cu semnul exclamării galben ⚠️:
   - Click dreapta pe el → **Remove Attachment**.
4. Click pe iconița de **Add Storage** (discul cu plusul albastru) de lângă "Controller: SATA".
5. În fereastra care se deschide, click pe **Add**.
6. Navighează la locația actuală a fișierului tău **`.vdi`** (hard disk-ul virtual) și selectează-l.
7. Click **Choose** apoi **OK**.
8. Pornește mașina.
