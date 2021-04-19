# ACL Manager for controller RUNOS

***

## 1. Install application

1. First of all, you must install [RUNOS](https://github.com/ARCCN/runos).

2. Then go to the apps folder:

    ```bash
    cd /runos/src/apps
    ```

3. Get application sources:

    ```bash
    git clone http://<application repository path>/acl-manager.git
    ```

4. Change default settings in the settings.json to the ones you need:

    ```json
    {
    "name": "acl-manager",
    "rest": false,
    "cli": false,
    "rules": {
        "10.0.0.1": ["10.0.0.6", "10.0.0.7"],
        "10.0.0.2": ["10.0.0.5", "10.0.0.7"],
        "10.0.0.3": ["10.0.0.5", "10.0.0.6"]
     }
    }
    ```

5. Run `nix-shell` inside runos directory and rebuild RUNOS:

    ```bash
    cd ../..
    nix-shell

    cd build
    cmake ..
    make
    ```
   

## 2. Application testing

1. Start RUNOS controller:

	```bash
	cd runos
	nix-shell
	./build/runos -c ../runos-settings.json
	```

2. Start a network topology in Mininet:

	```bash
	sudo python topology.py
	```

3. Check that **h1** can get access to **h5** but can't get access to **h6** and **h7**:

    ```bash
   h1 curl h5
   h1 curl h6
   h1 curl h7
	```