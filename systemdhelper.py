from subprocess import call
from enquiries import confirm

if confirm("Create SYSTEMD unit?"):
    with open("/etc/systemd/user/dl-jwtserver.service", "w") as writer:
        writer.write("""[Unit]
Description=JWT authentication service over HTTP.
After=network.target

[Service]
ExecStart={}

[Install]
WantedBy=multi-user.target""".format(input("Enter path to start script: ")))
    call("sudo systemctl enable dl-jwtserver", shell=True)
    if confirm("Start service?"):
        call("sudo systemctl start dl-jwtserver", shell=True)
