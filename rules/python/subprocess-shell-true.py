import subprocess


def run(user_arg):
    # ruleid: python.subprocess-shell-true
    subprocess.call("ls " + user_arg, shell=True)
    # ruleid: python.subprocess-shell-true
    subprocess.run(f"grep {user_arg} /var/log/app.log", shell=True, check=True)
    # ok: python.subprocess-shell-true
    subprocess.run(["ls", user_arg])
    # ok: python.subprocess-shell-true
    subprocess.run("uptime", shell=True)
