## Debian install
### install and configure jumphost service:
```
git clone <this repo>
cd jumphost
sudo ln -sf `pwd`/jumphost.py /usr/local/bin/jumphost
echo "OWNER=$(whoami)" | sudo tee /etc/default/jumphost
```
### create credentials.yaml with following content:
```
corp:
  username: <User>
  password: <PIN>
```
### Autostart service(WSL):
```
sudo cp etc/init.d/jumphost /etc/init.d
sudo chown root:root /etc/init.d/jumphost
sudo chmod 755 /etc/init.d/jumphost
echo "DAEMON_ARGS=\"-vv -l -p --uid \$OWNER --forti $(pwd)/jumphost.yaml\"" | sudo tee -a /etc/default/jumphost
sudo update-rc.d jumphost defaults
sudo apt install sysv-rc
```
### Autostart service(systemd):
```
sudo cp etc/systemd/system/jumphost.service /etc/systemd/system/
sudo sed -i "s/root/$(whoami)/g" /etc/systemd/system/jumphost.service
echo "DAEMON_ARGS=\"-vv -p --forti $(pwd)/jumphost.yaml\"" | sudo tee -a /etc/default/jumphost
sudo systemctl enable jumhost.service
```
### install required packages:
```
echo 'APT::Default-Release "stable";' | sudo tee /etc/apt/apt.conf.d/99defaultrelease
echo 'deb http://mirrors.kernel.org/debian/ sid main contrib non-free' | sudo tee /etc/apt/sources.list.d/unstable.list
sudo apt update
sudo apt -t sid install python3 python3-pip python3-daemon python3-pexpect python3-setproctitle python3-yaml python3-pycryptodome  python3-asyncssh python3-uvloop connect-proxy python3-pykeepass
sudo pip3 install aiosocks
```
### start jumphost:
```
sudo service jumhost start
```
### update bash profile:
```
echo "export http_proxy=socks5h://localhost:8118" >> ~/.profile
echo "export https_proxy=socks5h://localhost:8118" >> ~/.profile
```
## Proxy switcher for Chrome:
Can be installed from [Chrome Web Store](https://chrome.google.com/webstore/detail/proxy-switcher-and-manage/onnfghpihccifgojkpnnncpagjcdbjod)
### Proxy switcher PAC Script URL:
```
http://localhost:8000
```
