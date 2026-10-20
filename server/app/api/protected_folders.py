import os
import re
from fastapi import APIRouter, HTTPException, Query, status
from typing import List, Optional
from ..models.schemas import (
    ProtectedFolderCreate,
    ProtectedFolderUpdate,
    ProtectedFolderResponse
)
from ..database.db import get_db, utc_now_iso

router = APIRouter(prefix="/api/protected-folders", tags=["Protected Folder Policies"])

def validate_windows_folder_path(path_str: str) -> str:
    if not path_str or len(path_str.strip()) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Folder path must be at least 3 characters long."
        )
    
    clean_path = path_str.strip()
    norm = os.path.normpath(clean_path)

    # Validate that it is an absolute drive path (e.g. C:\..., D:\...)
    drive_match = re.match(r'^[a-zA-Z]:[\\/]', norm)
    if not drive_match:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Folder path must be an absolute Windows drive path (e.g. C:\\SecureData)."
        )

    # Disallow protecting the root drive itself (e.g. C:\) to prevent accidental system locking
    if re.match(r'^[a-zA-Z]:[\\/]?$', norm):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot protect an entire root drive partition. Please specify a dedicated folder (e.g. C:\\SecureData)."
        )

    # Check for invalid characters in Windows paths
    invalid_chars = ['<', '>', '"', '|', '?', '*']
    for char in invalid_chars:
        if char in norm:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Folder path contains invalid character '{char}'."
            )

    return norm

@router.get("", response_model=List[ProtectedFolderResponse])
def list_protected_folders(enabled_only: bool = Query(False, description="Filter for client synchronization")):
    folders = []
    with get_db() as conn:
        cursor = conn.cursor()
        if enabled_only:
            cursor.execute("""
                SELECT id, folder_path, description, is_enabled, created_at, updated_at
                FROM protected_folder_policies
                WHERE is_enabled = 1
                ORDER BY id ASC;
            """)
        else:
            cursor.execute("""
                SELECT id, folder_path, description, is_enabled, created_at, updated_at
                FROM protected_folder_policies
                ORDER BY id ASC;
            """)
        
        for r in cursor.fetchall():
            folders.append(ProtectedFolderResponse(
                id=r["id"],
                folder_path=r["folder_path"],
                description=r["description"] or "",
                is_enabled=bool(r["is_enabled"]),
                created_at=r["created_at"] or "",
                updated_at=r["updated_at"]
            ))
    return folders

@router.post("", response_model=ProtectedFolderResponse, status_code=status.HTTP_201_CREATED)
def create_protected_folder(data: ProtectedFolderCreate):
    validated_path = validate_windows_folder_path(data.folder_path)
    now = utc_now_iso()

    with get_db() as conn:
        cursor = conn.cursor()
        # Check uniqueness case-insensitively for Windows paths
        cursor.execute("SELECT id FROM protected_folder_policies WHERE LOWER(folder_path) = LOWER(?);", (validated_path,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Protected folder policy already exists for '{validated_path}'."
            )

        cursor.execute("""
            INSERT INTO protected_folder_policies (folder_path, description, is_enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?);
        """, (validated_path, data.description or "", 1 if data.is_enabled else 0, now, now))
        folder_id = cursor.lastrowid

    return ProtectedFolderResponse(
        id=folder_id,
        folder_path=validated_path,
        description=data.description or "",
        is_enabled=bool(data.is_enabled),
        created_at=now,
        updated_at=now
    )

@router.put("/{folder_id}/toggle", response_model=ProtectedFolderResponse)
def toggle_protected_folder(folder_id: int):
    now = utc_now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, folder_path, description, is_enabled, created_at FROM protected_folder_policies WHERE id = ?;", (folder_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Protected folder policy not found.")

        new_state = 0 if row["is_enabled"] else 1
        cursor.execute("""
            UPDATE protected_folder_policies
            SET is_enabled = ?, updated_at = ?
            WHERE id = ?;
        """, (new_state, now, folder_id))

        return ProtectedFolderResponse(
            id=row["id"],
            folder_path=row["folder_path"],
            description=row["description"] or "",
            is_enabled=bool(new_state),
            created_at=row["created_at"] or "",
            updated_at=now
        )

@router.delete("/{folder_id}", response_model=dict)
def delete_protected_folder(folder_id: int):
    """
    Remove folder from protection policy without deleting its contents on the filesystem.
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT folder_path FROM protected_folder_policies WHERE id = ?;", (folder_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Protected folder policy not found.")

        folder_path = row["folder_path"]
        cursor.execute("DELETE FROM protected_folder_policies WHERE id = ?;", (folder_id,))

    return {
        "status": "success",
        "message": f"Protected folder policy for '{folder_path}' removed successfully without deleting files.",
        "folder_id": folder_id
    }
