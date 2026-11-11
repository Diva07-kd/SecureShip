import subprocess

# Negative fixture: subprocess with argument list and shell=False (default)
def run_command_safe(args):
    return subprocess.run(["git", "status"], check=True)

def open_process_safe(binary_path, flags):
    return subprocess.Popen([binary_path] + flags, shell=False)
