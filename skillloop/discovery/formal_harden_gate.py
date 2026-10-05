"""Independent current development review without releasing a private roster."""
import os
from skillloop.discovery.formal_roster_gate import freeze_roster


def main():
    os.umask(0o077)
    return freeze_roster(assignment_path='/assignment/job.json',
        whole_round_manifest_path='/whole-round/manifest.json',evaluation_directory='/evaluation',
        task_review_directory='/task-reviews',application_directory='/applications',
        scan_directory='/scans',scan_review_directory='/scan-reviews',
        authority_directory='/authority-projection',output_directory='/roster',harden_only=True)


if __name__=='__main__':main()
