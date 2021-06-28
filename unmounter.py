"""
  unmounter
  This program's purpose is to unmount the mounted drives.
  It was made solely for expermentation purposes.
  Made by Ulfur Johann Edvardsson as a part of a M.Sc. thesis at DTU compute.
"""

import subprocess





if __name__ == '__main__':
    print("Unmounting Encrypted drive")

    subprocess.run(['sudo', 'umount', "/mnt/ntfs"], stdout=subprocess.PIPE)
    subprocess.run(['sudo', 'umount', "/mnt/bitlocker"], stdout=subprocess.PIPE)

    print("Drives unmounted")

