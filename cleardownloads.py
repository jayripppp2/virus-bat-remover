import os
import shutil

def clean_downloads(directory):
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
                print(f'Deleted {file_path}')
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
                print(f'Deleted {file_path}')
        except Exception as e:
            print(f'Failed to delete {file_path}. Reason: {e}')

def clean_temp():
    temp_folders = [os.getenv('TEMP'), os.getenv('TMP')]
    for folder in temp_folders:
        if folder:
            clean_downloads(folder)

def clean_desktop():
    desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
    clean_downloads(desktop_path)

def clean_appdata():
    appdata_path = os.getenv('APPDATA')
    clean_downloads(appdata_path)

# Example usage:
if __name__ == "__main__":
    clean_downloads('/path/to/your/downloads/folder')
    clean_desktop()
    clean_temp()
    clean_appdata()
