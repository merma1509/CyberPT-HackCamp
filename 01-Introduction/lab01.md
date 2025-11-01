**Lab 0 (Day 0): CyberED Labs - Welcome VPN Check** step-by-step.

#### 1. **Download the VPN Config**
* Go to the lab dashboard.
* Click **“VPN config”** and download the `.ovpn` file.
#### 2. **Connect to VPN**
Using OpenVPN on Kali or your local machine:
```bash
sudo openvpn .ovpn downloaded
```
> Accept if prompted to allow permissions. Wait until it says `Initialization Sequence Completed`.

#### 3. **Access the Lab Web Page**
Check the lab connection info – it usually gives you a private IP like `http://10.10.0.7`.
In your browser (while still connected to VPN), go to: `http://10.10.0.7`

#### 4. **Find the Flag**

On the page that loads, you'll see a message like:

```
Welcome to CyberED Labs!
Your VPN is working fine.

FLAG: CyberED{vpn_connection_successful}
```