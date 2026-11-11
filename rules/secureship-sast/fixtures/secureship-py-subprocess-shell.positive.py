import subprocess

# Positive fixture: subprocess with shell=True
def run_command_in_shell(cmd):
    return subprocess.run(cmd, shell=True, check=True)

def open_process_shell(user_script):
    return subprocess.Popen(user_script, shell=True)
