from subprocess import call
from enquiries import confirm
from os.path import isfile

if confirm("Create SYSTEMD unit?"):
    with open("/etc/systemd/system/dl-jwtserver.service", "w") as writer:
        writer.write("""[Unit]
Description=JWT authentication service over HTTP.
After=network.target

[Service]
ExecStart=cd {a} && {a}/start.sh

[Install]
WantedBy=multi-user.target""".format(a=input("Enter path to installation: ")))
    prefix = ""
    if isfile("/bin/sudo"):
        prefix = "sudo "
    call(prefix + "systemctl enable dl-jwtserver", shell=True)
    if confirm("Start service?"):
        call(prefix + "systemctl start dl-jwtserver", shell=True)
