from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, status, Form
from sqlalchemy.orm import Session

from onyx.auth.users import current_user
from onyx.server.auth_check import require_write
from onyx.db.engine import get_session
from onyx.db.models import User, UserDocument
from onyx.server.documents.models import DocumentResponse
from onyx.utils.logger import setup_logger

logger = setup_logger()
router = APIRouter(prefix="/documents", tags=["documents"])


@router.post("/upload", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    file: UploadFile = File(...),
    is_public: bool = Form(False),
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> DocumentResponse:
    """
    Upload a document file with OAuth write permission.
    
    Args:
        file: Document file to upload
        is_public: Whether document should be public
        user: Authenticated user with write permission
        db_session: Database session
        
    Returns:
        Created document metadata
        
    Raises:
        HTTPException: 400 if file invalid, 413 if file too large
    """
    logger.info(f"User {user.email} uploading document: {file.filename}")
    
    # Validate file
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required"
        )
    
    # Check file size (10MB limit)
    if file.size and file.size > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds 10MB limit"
        )
    
    # Check file type
    allowed_types = ["text/plain", "text/markdown", "application/pdf", "text/html"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type {file.content_type} not allowed"
        )
    
    try:
        # Read and process file content
        content = await file.read()
        text_content = content.decode('utf-8') if file.content_type and file.content_type.startswith('text/') else ""
        
        # Create document record
        new_document = UserDocument(
            title=file.filename,
            content=text_content,
            is_public=is_public,
            created_by=user.id,
            updated_by=user.id
        )
        
        db_session.add(new_document)
        db_session.commit()
        db_session.refresh(new_document)
        
        logger.info(f"Document {new_document.id} uploaded by user {user.email}")
        return DocumentResponse.from_user_document(new_document)
        
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File content is not valid UTF-8"
        )
    except Exception as e:
        logger.error(f"Error uploading document for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload document"
        )


@router.post("/bulk-upload", response_model=List[DocumentResponse])
async def bulk_upload_documents(
    files: List[UploadFile] = File(...),
    is_public: bool = Form(False),
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> List[DocumentResponse]:
    """
    Bulk upload multiple documents with OAuth write permission.
    
    Args:
        files: List of document files to upload
        is_public: Whether documents should be public
        user: Authenticated user with write permission
        db_session: Database session
        
    Returns:
        List of created document metadata
    """
    logger.info(f"User {user.email} bulk uploading {len(files)} documents")
    
    if len(files) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot upload more than 50 files at once"
        )
    
    created_documents = []
    errors = []
    
    for file in files:
        try:
            # Process each file individually
            doc_response = await upload_document(file, is_public, user, db_session)
            created_documents.append(doc_response)
        except HTTPException as e:
            errors.append(f"{file.filename}: {e.detail}")
        except Exception as e:
            errors.append(f"{file.filename}: Upload failed")
    
    if errors and not created_documents:
        # All uploads failed
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"All uploads failed: {'; '.join(errors)}"
        )
    elif errors:
        # Some uploads failed
        logger.warning(f"Bulk upload partially failed for user {user.email}: {errors}")
    
    logger.info(f"Bulk upload completed: {len(created_documents)} successful, {len(errors)} failed")
    return created_documents
