from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from onyx.auth.users import current_user
from onyx.server.auth_check import require_read, require_write, require_admin, get_oauth_permission
from onyx.db.engine import get_session
from onyx.db.models import User, UserDocument
from onyx.server.documents.models import (
    DocumentResponse,
    DocumentCreate,
    DocumentUpdate,
    DocumentSearchRequest
)
from onyx.utils.logger import setup_logger

logger = setup_logger()
router = APIRouter(prefix="/documents", tags=["documents"])


@router.get("", response_model=List[DocumentResponse])
async def get_documents(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    user: User = Depends(require_read),  # OAuth permission required
    db_session: Session = Depends(get_session)
) -> List[DocumentResponse]:
    """
    Retrieve documents with OAuth read permission.
    
    Args:
        limit: Maximum number of documents to return
        offset: Number of documents to skip
        search: Optional search query
        user: Authenticated user with read permission
        db_session: Database session
        
    Returns:
        List of documents the user has access to
    """
    logger.info(f"User {user.email} requesting documents (limit={limit}, offset={offset})")
    
    try:
        query = db_session.query(UserDocument)
        
        # Apply search filter if provided
        if search:
            query = query.filter(UserDocument.title.ilike(f"%{search}%"))
        
        # Apply user-specific filtering based on permission level
        # Read users see only public documents or their own
        user_permission = await get_oauth_permission(user)
        if user_permission == "read":
            query = query.filter(
                or_(UserDocument.is_public == True, UserDocument.created_by == user.id)
            )
        # Write and admin users see all documents (no additional filtering)
        
        documents = query.offset(offset).limit(limit).all()
        
        logger.info(f"Returning {len(documents)} documents to user {user.email}")
        return [DocumentResponse.from_user_document(doc) for doc in documents]
        
    except Exception as e:
        logger.error(f"Error retrieving documents for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve documents"
        )


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: int = Path(..., description="Document ID"),
    user: User = Depends(require_read),  # OAuth permission required
    db_session: Session = Depends(get_session)
) -> DocumentResponse:
    """
    Get a specific document by ID with OAuth read permission.
    
    Args:
        document_id: ID of the document to retrieve
        user: Authenticated user with read permission
        db_session: Database session
        
    Returns:
        Document data
        
    Raises:
        HTTPException: 404 if document not found or access denied
    """
    logger.info(f"User {user.email} requesting document {document_id}")
    
    document = db_session.query(UserDocument).filter(UserDocument.id == document_id).first()
    if not document:
        logger.warning(f"Document {document_id} not found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    # Check if user has access to this document
    user_permission = await get_oauth_permission(user)
    if user_permission == "read" and not document.is_public and document.created_by != user.id:
        logger.warning(f"User {user.email} denied access to private document {document_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to private document"
        )
    
    return DocumentResponse.from_user_document(document)


@router.post("", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def create_document(
    document_data: DocumentCreate,
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> DocumentResponse:
    """
    Create a new document with OAuth write permission.
    
    Args:
        document_data: Document creation data
        user: Authenticated user with write permission
        db_session: Database session
        
    Returns:
        Created document data
        
    Raises:
        HTTPException: 400 if validation fails, 500 if creation fails
    """
    logger.info(f"User {user.email} creating document: {document_data.title}")
    
    try:
        # Validate document data
        if not document_data.title or len(document_data.title.strip()) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Document title is required"
            )
        
        # Create document
        new_document = UserDocument(
            title=document_data.title,
            content=document_data.content or "",
            is_public=document_data.is_public,
            created_by=user.id,
            updated_by=user.id
        )
        
        db_session.add(new_document)
        db_session.commit()
        db_session.refresh(new_document)
        
        logger.info(f"Document {new_document.id} created by user {user.email}")
        return DocumentResponse.from_user_document(new_document)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating document for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create document"
        )


@router.put("/{document_id}", response_model=DocumentResponse)
async def update_document(
    document_id: int = Path(..., description="Document ID"),
    *,
    document_data: DocumentUpdate,
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> DocumentResponse:
    """
    Update an existing document with OAuth write permission.
    
    Args:
        document_id: ID of the document to update
        document_data: Document update data
        user: Authenticated user with write permission
        db_session: Database session
        
    Returns:
        Updated document data
        
    Raises:
        HTTPException: 404 if document not found, 403 if access denied
    """
    logger.info(f"User {user.email} updating document {document_id}")
    
    document = db_session.query(UserDocument).filter(UserDocument.id == document_id).first()
    if not document:
        logger.warning(f"Document {document_id} not found for update")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    # Check if user can update this document
    user_permission = await get_oauth_permission(user)
    if user_permission != "admin" and document.created_by != user.id:
        logger.warning(f"User {user.email} denied update access to document {document_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only update your own documents"
        )
    
    try:
        # Update document fields
        if document_data.title is not None:
            document.title = document_data.title
        if document_data.content is not None:
            document.content = document_data.content
        if document_data.is_public is not None:
            document.is_public = document_data.is_public
        
        document.updated_by = user.id
        # updated_at will be set automatically by onupdate=func.now()
        
        db_session.commit()
        db_session.refresh(document)
        
        logger.info(f"Document {document_id} updated by user {user.email}")
        return DocumentResponse.from_user_document(document)
        
    except Exception as e:
        logger.error(f"Error updating document {document_id} for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update document"
        )


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    document_id: int = Path(..., description="Document ID"),
    user: User = Depends(require_write),  # OAuth write permission required
    db_session: Session = Depends(get_session)
) -> None:
    """
    Delete a document with OAuth write permission.
    
    Args:
        document_id: ID of the document to delete
        user: Authenticated user with write permission
        db_session: Database session
        
    Raises:
        HTTPException: 404 if document not found, 403 if access denied
    """
    logger.info(f"User {user.email} deleting document {document_id}")
    
    document = db_session.query(UserDocument).filter(UserDocument.id == document_id).first()
    if not document:
        logger.warning(f"Document {document_id} not found for deletion")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    # Check if user can delete this document
    user_permission = await get_oauth_permission(user)
    if user_permission != "admin" and document.created_by != user.id:
        logger.warning(f"User {user.email} denied delete access to document {document_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only delete your own documents"
        )
    
    try:
        db_session.delete(document)
        db_session.commit()
        
        logger.info(f"Document {document_id} deleted by user {user.email}")
        
    except Exception as e:
        logger.error(f"Error deleting document {document_id} for user {user.id}: {e}")
        db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete document"
        )


@router.post("/search", response_model=List[DocumentResponse])
async def search_documents(
    search_request: DocumentSearchRequest,
    user: User = Depends(require_read),  # OAuth permission required
    db_session: Session = Depends(get_session)
) -> List[DocumentResponse]:
    """
    Advanced document search with OAuth read permission.
    
    Args:
        search_request: Search parameters
        user: Authenticated user with read permission
        db_session: Database session
        
    Returns:
        List of matching documents
    """
    logger.info(f"User {user.email} performing document search")
    
    try:
        query = db_session.query(UserDocument)
        
        # Apply search filters
        if search_request.query:
            query = query.filter(
                or_(
                    UserDocument.title.ilike(f"%{search_request.query}%"),
                    UserDocument.content.ilike(f"%{search_request.query}%")
                )
            )
        
        # Apply permission-based filtering
        user_permission = await get_oauth_permission(user)
        if user_permission == "read":
            query = query.filter(
                or_(UserDocument.is_public == True, UserDocument.created_by == user.id)
            )
        
        # Apply other filters
        if search_request.created_after:
            query = query.filter(UserDocument.created_at >= search_request.created_after)
        if search_request.created_before:
            query = query.filter(UserDocument.created_at <= search_request.created_before)
        
        documents = query.limit(search_request.limit or 100).all()
        
        logger.info(f"Search returned {len(documents)} documents for user {user.email}")
        return [DocumentResponse.from_user_document(doc) for doc in documents]
        
    except Exception as e:
        logger.error(f"Error in document search for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Search failed"
        )
