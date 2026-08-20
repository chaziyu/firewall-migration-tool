from typing import Optional
from fwmigrate.jobs.models import MigrationJob

class SnapshotError(Exception):
    pass

class TargetSnapshotManager:
    """
    Abstracts vendor-specific backup and restore operations.
    Unlike 'terraform destroy', this handles full device state snapshots
    which are required for safe rollbacks on enterprise firewalls.
    """
    
    def create_snapshot(self, job: MigrationJob) -> str:
        """
        Takes a pre-deployment snapshot of the target device.
        Returns a unique snapshot ID or reference URI.
        """
        raise NotImplementedError("Subclasses must implement create_snapshot")
        
    def verify_snapshot(self, snapshot_id: str) -> bool:
        """
        Verifies that a snapshot was successfully created and is available for restore.
        """
        raise NotImplementedError("Subclasses must implement verify_snapshot")
        
    def restore_snapshot(self, job: MigrationJob, snapshot_id: str) -> bool:
        """
        Restores the target device to the state captured in the snapshot.
        """
        raise NotImplementedError("Subclasses must implement restore_snapshot")
        
    def verify_restore(self, job: MigrationJob, snapshot_id: str) -> bool:
        """
        Validates the device has successfully rolled back (e.g. by comparing configuration hashes).
        """
        raise NotImplementedError("Subclasses must implement verify_restore")


class PaloAltoSnapshotManager(TargetSnapshotManager):
    """
    Implementation of snapshot management for PAN-OS devices.
    """
    
    def create_snapshot(self, job: MigrationJob) -> str:
        # Pseudo-code for PAN-OS API:
        # 1. request system config save
        # snapshot_name = f"pre-migration-{job.id}.xml"
        # 2. return snapshot_name
        return f"pre-migration-{job.id}.xml"
        
    def verify_snapshot(self, snapshot_id: str) -> bool:
        # Pseudo-code for PAN-OS API:
        # check if snapshot_id exists in 'show config saved'
        return True
        
    def restore_snapshot(self, job: MigrationJob, snapshot_id: str) -> bool:
        # Pseudo-code for PAN-OS API:
        # 1. request system config load name={snapshot_id}
        # 2. request commit
        return True
        
    def verify_restore(self, job: MigrationJob, snapshot_id: str) -> bool:
        # Pseudo-code for PAN-OS API:
        # check commit status
        return True
