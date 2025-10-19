## Getting Started with Tezos BLS Signer

I’ve been baking on tezos for years using a Ledger Nano S (and later an S+) and TezBake, an fantastic product for small bakers developed by the team at [Tez Capital](https://tez.capital/). Unfortunately, the Ledger devices and the Ledger Tezos Baking App do not support BLS keys. So with the arrival of the Seoul protocol and BLS keys on mainnet, I got started experimenting with the new [BLS Signer](https://forum.tezosagora.org/t/announcing-the-raspberry-pi-bls-signer-for-tezos-bakers/6911/4) developed by the team at Nomadic Labs. BLS Signer is basically a Raspberry Pi Zero running octez-signer and configured to connect to a baking machine via USB. While the Tez Capital team is working on support for BLS Signer or an alternative they are developing, TezBake does not currently support the device. So, I had to transition to using octez-baker directly. I wasn’t particularly eager to do so since in my experience TezBake is much easier to set up then octez-baker directly. But my Ledger Nano S+ decided to break on me last week, creating urgency. Here is what I did to make the switch.

### Step 1: Install Ubuntu 24.04 LTS

Whenever I make significant chnages to my baking setup I start fresh with a clean install of Ubuntu 24.04 LTS. I have two mini PCs that I use to bake but I am careful that only one is in service at any given time (don’t want any chance to double bake). I use Ubuntu Desktop instead of Server so I can connect a monitor, keyboard, and mouse. Once everything is installed and configured, I remove the monitor and peripherals and go “headless”, using SSH from my laptop whenever I need to log into the baker machine to monitor and make changes. 

[Ubuntu Desktop Download Link](https://ubuntu.com/download/desktop)

### Step 2: Install the Octez Binaries

The procedure for installing Octez has changed over time as the core developers have made improvements. Unfortunately, this means the internet is littered with incorrect and/or out of date instructions. For example, the Serokell repository is depreciated, and tezos packaging is now done by Nomadic Labs. [These](https://octez.tezos.com/docs/introduction/howtoget.html) installation instructions seem to be keeped mostly up to date. These are my notes for getting Octez on fresh instllation of Ubuntu 24.04:

First, install some tools that will be needed at some point including curl and openssh-server because I wish to log into the baker machine via ssh after setup from your local area network. Also install net-tools, which will give you the ifconfig tool used to spin up a network interface for the BLS signer. 

```
sudo apt-get update
sudo apt-get install curl
sudo apt-get install openssh-server
Sudo apt-get net-tools
```

Then, open a terminal, add the distribution and release as variables in your shell environment. 

```
export distribution=ubuntu
export release=noble
```

Download an ASCII armored public key from Nomadic Labs, pipe it through gpg to convert it into binary format, and save it as octez.gpg. This key will be used to verify the nomadic labs repositories.

```
curl -s "https://packages.nomadic-labs.com/$distribution/octez.asc" | sudo gpg --dearmor -o /etc/apt/keyrings/octez.gpg
```

Use echo to form the full repository string for your distribution and release then pipe this string to tee which will write it to a filed octez.list in your apt repository sources.list.d directory.

```
echo "deb [signed-by=/etc/apt/keyrings/octez.gpg] https://packages.nomadic-labs.com/$distribution $release main" | sudo tee /etc/apt/sources.list.d/octez.list
```

Update apt (or apt-get) and install octez. You just need to include octez-baker in the command because octez-client, octez-node, octez-signer, octez-dal-node, and octez-accuser are all dependencies. 

```
sudo apt-get update
sudo apt-get install octez-baker
```

During the installation process you will be prompted with the option to configure octez-node. I recommend doing so. I set up the node as in rolling mode on mainnet, with instructions to download a snapshot when it is first started up, and with the liquidity toggle vote set to PASS. 

[[ADD IN THE DETAILS WHEN YOU DO THIS AGAIN]]

### Step 3: Build and Setup BLS Signer

The official BLS Signer repository is [here](https://gitlab.com/nomadic-labs/tezos-rpi-bls-signer).

After assembling the hardware, I took the route of installing the pre-built image. I will probably build from scratch later so I can get a chance to really understand the system. I used the Raspberry Pi Imager application on my laptop to flash the image to the microSD card. For the operating system option choose the last option “Use custom”. The instructions on setting up and configuring the device once it is built and loaded with the image are good, and I didn’t run into any problems. However, I did run into some issues configuring my host PC to connect to the device via USB. 

First, the `add_udev_rules.sh` script is necessary to configure Ubuntu to connect to the BLS signer device via USB and spin up a network interface so it is addressable from the host via TCP. However, the script installs rules in your system that use `ifconfig`, which must be installed if you are starting from a fresh build like I am (did this above).

Second, I had issues with the device not connecting to my host. My best guess is this was because it was getting both power and connectivity via a single USB cable. It seems that when my host PC reboots it cuts power to the BLS signer momentarily causing it to reboot too. On reboot it tries and fails to connect to the BLS signer because the attempt is made prior to the device fully rebooting. Since the device is using an e-paper display, you may not be immediately aware of it losing power or trying to reboot. To fix this issue I connected the device to my host PC via one USB cable and then used the second dedicated USB power port (this is the one nearest to the end of the device) to plug it into a wall receptacle. Now even if my host PC reboots or the USB cable is disconnected from the host, the BLS signer never loses power and reboots. 

### Step 4: Setup and Configure Octez

This is the part that many small bakers who have been using TezBake may need the most. In order to set everything up to bake you need to do the following.

* Configure and start octez-node
* Configure and start octez-dal-node
* Import the BLS keys (two of them) into octez-client from the BLS signer
* Configure and start octez-baker

If you intend to run octez-node, octez-dal-node, and octez-baker as services that start on boot and restart when they go down, the process involves modifying some configuration files and importantly, this must be done as the tezos user created during the octez installation process, because the services are configured to start under this user. 

Assuming you have already configured octez-node during the installation process, start the octez-node service.

```
sudo systemctl start octez-node.service
```

Don’t be alarmed when this command hang for a very long time. On first start up it must download the snapshot (which is over 10 GB for a rolling node), unpack this snapshot, and launch. It takes a long time. Just go get a snack or some coffee and come back later. Don’t proceed until the terminal prompt returns. 

Next, you must configure and start the octez-dal-node. This needs to be done as the tezos user if you intend to run octez-baker as a service. Change to the tezos user.

```
sudo su - tezos
```

Create and initialize the dal node configuration file to point to your baker. Note, that this is the baker manager key registered on the blockchain (the tz address, not an alias you may be using with octez-client, and not the BLS keys on the BLS signer device that will be used as consensus and companion keys). 

```
octez-dal-node config init --endpoint http://127.0.0.1:8732 --attester-profiles=tz1tHisIsMyreGiSterEdBakerManAGERKeY
```

Exit the tezos users (type exit in the terminal) and restart the dal node using the new configuration

```
sudo systemctl restart octez-dal-node.service
```

Now, import the keys from the BLS signer into tezos users data files for octez-client. Switch back to the tezos user.

```
sudo su - tezos
```

If everything is set up correctly, the BLS signer should be accessible over TCP on IP address 10.0.0.1.

```
octez-client list known remote keys tcp://10.0.0.1:7732
```

This command sends a request to octez-signer running on the raspberry pi device listening on port 7732. The request instructs octez-signer to return known public keys, which will be BLS keys and correspond to the tz4 addresses created by the device when it was initialized. The command will return information like the following (these are not my real BLS public keys)

```
Tezos remote known keys:
    tz4YXJteWF0bW9zcGhlcmVydW5uaW5naGVyZ
    tz4GxvY2FseW91d2hlbmR1bGx0cmFjZWFpcn
```

Import the first one as your new baker consensus key. Here I am assigning the alias baker_consensus to this key.

```
octez-client import secret key baker_consensus \ tcp://10.0.0.1:7732/tz4YXJteWF0bW9zcGhlcmVydW5uaW5naGVyZ
```		   

Import the second one as your new baker companion key. 

```
octez-client import secret key baker_companion \ tcp://10.0.0.1:7732/tz4GxvY2FseW91d2hlbmR1bGx0cmFjZWFpcn  
```

My understanding is the companion key is used to sign DAL attestations. I’m not sure and I don’t currently understand why a separate key is needed besides it having to do with signature aggregation, which BLS elliptic curve cryptography enables. 

The final step is to set up octez-baker. This will involve modifying a default configuration file that imports options into the execution string in the octez-baker.service (actually octez-baker@.service). If you view the systemctl service file that starts octez-baker, octez-baker.service, it calls a script which calls octez-baker@.service where the @ passes the protocol name, which is referenced in the octez-baker@.service file as %i.  (currently I am not running the protocol agnostic verision). Anyway, it is complicated and I need to spend more time with these scripts to feel like I fully know what they are doing. The service files are in `/usr/lib/systemd/system` file I needed to modify to launch the baker with the correct execution string is `/etc/default/octez-baker'. Here is what my `octez-baker' file looks like

```
LQVOTE=pass
BAKER_KEY=
AGNOSTIC_BAKER=false
BAKING_KEY="baker_consensus baker_companion ledger_baker"
RUNTIME_OPTS="--keep-alive --dal-node http://127.0.0.1:10732"
```

The `BAKER_KEY` variable apparently does nothing but is in there to start so I kept it. It is probably a typo because the variable that is actually referenced in the execution string in octez-baker@.service is `$BAKING_KEYS', which is what I added. The `RUNTIME_OPTS` points to my DAL node so I can participate in DAL attestations and the `BAKING_KEY` variable lists both of the BLS baking keys using the aliases created when they were imported. The `ledger_baker` alias is my tz1 baking key currenlty signing from my Ledger Nano S+. This is here because my new BLS keys will not take effect until a future cycle. See below for more details about importing a key from the ledger device and setting the BLS keys as my future consensus and companion key.

### Aside: Getting Ledger Nano S Plus Working and Setting the BLS Keys for Consensus and Companion

Initialize the Nano S Plus with a new or existing seed phrase. Use a 24 word seed to get a full 32-bytes (256-bits) of entropy. Don’t make it easier for quantum computers to crack your secret key.

Use ledger live to Install the tezos wallet and tezos baker apps. The latter requires that you first enable developer mode. 

Set up udev rules so you can connect to the ledger device. Simply running the script Ledger provides will probably not work because it will not grant sufficient privileges to the tezos user. Instead, create a custom udev rules file that grants privileges to all members of the plugdev group, which is a group that allows users to mount and unmount usb connected devices.

```
echo ‘SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", TAG+="uaccess", \
TAG+="udev-acl", MODE="0660", GROUP="plugdev"’ \
| sudo tee /etc/udev/rules.d/20-leger.rules
```

Then add tezos (and your own user account if you want) to the plugdev group.

```
sudo usermod -a -G plugdev tezos
```

Now reload the udev rules

```
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Now, switch to the tezos user.

```
sudo su - tezos
```

And import the baker key on the ledger.

```
octez-client list connected ledgers
```

This command will list several octez-client import secret key . . . options corresponding to different key types (tz1, tz2, or tz3). Assuming you are using keys derived in the conventional fashion with the default BIP32 path these will work. Pick the ed25519 path for a tz1 key, the secp256k1 path for a tz2 key, or the P-256 path for a tz3 key. The bip25519 path also results in a tz1 key but uses a more modern key derivation method fully compliant with BIP32 [[TEST IT OUT SOMETIME]]. Pick a key alias, below ledger_baker, and import the key substituting your correct import path. 

```
octez-client import secret key ledger_baker “ledger://weird-words-like-donkey/ed25519/0h/0h” 
```

By the way, this doesn’t actually import the secret key. It imports the public key and provides octez with information needed to send operations to the ledger device so they can be signed by the secret key. The secret key never leaves the ledger device. 

Now that my tezos delagate (manager) key is known to tezos-client I can use it to assign my BLS keys as my consensus and campanion keys taking affect on a future cycle.

```
octez-client --wait none set consensus key for ledger_baker to baker_consensus
octez-client --wait none set companion key for <DELEGATE> to baker_companion
```

