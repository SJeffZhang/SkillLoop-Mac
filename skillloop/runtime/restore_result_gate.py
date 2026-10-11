import os
from skillloop.runtime.archive_results import run

if __name__=='__main__':
    os.umask(0o077);run()
