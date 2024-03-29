import shutil


"""This function check is there is enough space to save files in server."""
def check_disk_space(path: str, required_space: int ) -> bool:
    disk_usage = shutil.disk_usage(path)
    free_space = disk_usage.free
    if free_space >= required_space:
        return True
    else:
        print("[ERROR] The server does not have enough space to create the file.")
        return False



