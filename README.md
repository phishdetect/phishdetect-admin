# PhishDetect Admin

This software is part of the PhishDetect project.

This is a simple Flask web application that is meant to run locally in order to remotely connect and manage a PhishDetect Node. You can simply install it with:

```
sudo pip3 install -I phishdetect-admin
```

Once installed, you can launch it with:

```
phishdetect-admin
```

It will spawn a local webserver and automatically open a tab on your default browser pointing to it. You will then be asked to configure the PhishDetet Node you wish to operate by providing the base URL (e.g. https://phishdetect.example.com) and your API key. The API key can be generated using phishdetect-node/scripts/add_user.py
