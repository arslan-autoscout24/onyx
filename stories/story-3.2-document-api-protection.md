# Story 3.2: Document API Permission Protection

## Overview
**Sprint**: 3 - Authorization Middleware  
**Story ID**: 3.2  
**Title**: Document API Permission Protection  
**Priority**: P1 - High  
**Estimate**: 1.5 days  
**Dependencies**: Story 3.1 (OAuth Permission Dependencies)

## Description
Apply OAuth permission-based access control to all document-related API endpoints using the newly created permission dependencies. This ensures that users can only access document operations appropriate to their permission level while maintaining backward compatibility.

## Acceptance Criteria
- [ ] GET `/documents` requires `read` permission
- [ ] POST `/documents` requires `write` permission  
- [ ] PUT/PATCH `/documents/{id}` requires `write` permission
- [ ] DELETE `/documents/{id}` requires `write` permission
- [ ] All endpoints return proper 403 errors for insufficient permissions
- [ ] Integration tests for each protected endpoint
- [ ] Performance tests show no degradation in document operations
- [ ] Backward compatibility maintained for existing authenticated users
- [ ] Audit logging for all permission-based access denials

## Technical Implementation

### Core Files to Modify

#### 1. Document Router Protection
**File**: `backend/onyx/server/documents/document.py`

```python
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from typing import List, Optional
from sqlalchemy.orm import Session

from onyx.auth.users import current_user
from onyx.server.auth_check import require_read, require_write, require_admin
from onyx.db.engine import get_session
from onyx.db.models import User, Document
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
        query = db_session.query(Document)
        
        # Apply search filter if provided
        if search:
            query = query.filter(Document.title.ilike(f"%{search}%"))
        
        # Apply user-specific filtering based on permission level
        # Read users see only public documents or their own
        user_permission = await get_user_oauth_permission(user.id)
        if user_permission == "read":
            query = query.filter(
                (Document.is_public == True) | (Document.created_by == user.id)
            )
        # Write and admin users see all documents
        
        documents = query.offset(offset).limit(limit).all()
        
        logger.info(f"Returning {len(documents)} documents to user {user.email}")
        return [DocumentResponse.from_document(doc) for doc in documents]
        
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
    
    document = db_session.query(Document).filter(Document.id == document_id).first()
    if not document:
        logger.warning(f"Document {document_id} not found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    # Check if user has access to this document
    user_permission = await get_user_oauth_permission(user.id)
    if user_permission == "read" and not document.is_public and document.created_by != user.id:
        logger.warning(f"User {user.email} denied access to private document {document_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to private document"
        )
    
    return DocumentResponse.from_document(document)

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
        new_document = Document(
            title=document_data.title,
            content=document_data.content or "",
            is_public=document_data.is_public if document_data.is_public is not None else False,
            created_by=user.id,
            updated_by=user.id
        )
        
        db_session.add(new_document)
        db_session.commit()
        db_session.refresh(new_document)
        
        logger.info(f"Document {new_document.id} created by user {user.email}")
        return DocumentResponse.from_document(new_document)
        
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
    document_data: DocumentUpdate = ...,
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
    
    document = db_session.query(Document).filter(Document.id == document_id).first()
    if not document:
        logger.warning(f"Document {document_id} not found for update")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    # Check if user can update this document
    user_permission = await get_user_oauth_permission(user.id)
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
        document.updated_at = datetime.utcnow()
        
        db_session.commit()
        db_session.refresh(document)
        
        logger.info(f"Document {document_id} updated by user {user.email}")
        return DocumentResponse.from_document(document)
        
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
    
    document = db_session.query(Document).filter(Document.id == document_id).first()
    if not document:
        logger.warning(f"Document {document_id} not found for deletion")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    # Check if user can delete this document
    user_permission = await get_user_oauth_permission(user.id)
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
        query = db_session.query(Document)
        
        # Apply search filters
        if search_request.query:
            query = query.filter(
                Document.title.ilike(f"%{search_request.query}%") |
                Document.content.ilike(f"%{search_request.query}%")
            )
        
        # Apply permission-based filtering
        user_permission = await get_user_oauth_permission(user.id)
        if user_permission == "read":
            query = query.filter(
                (Document.is_public == True) | (Document.created_by == user.id)
            )
        
        # Apply other filters
        if search_request.created_after:
            query = query.filter(Document.created_at >= search_request.created_after)
        if search_request.created_before:
            query = query.filter(Document.created_at <= search_request.created_before)
        
        documents = query.limit(search_request.limit or 100).all()
        
        logger.info(f"Search returned {len(documents)} documents for user {user.email}")
        return [DocumentResponse.from_document(doc) for doc in documents]
        
    except Exception as e:
        logger.error(f"Error in document search for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Search failed"
        )
```

#### 2. Document Upload Endpoint Protection
**File**: `backend/onyx/server/documents/upload.py`

```python
from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, status
from typing import List
from onyx.server.auth_check import require_write
from onyx.db.models import User
from onyx.utils.logger import setup_logger

logger = setup_logger()
router = APIRouter(prefix="/documents", tags=["documents"])

@router.post("/upload", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    file: UploadFile = File(...),
    is_public: bool = False,
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
    if file.size > 10 * 1024 * 1024:
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
        text_content = content.decode('utf-8') if file.content_type.startswith('text/') else ""
        
        # Create document record
        new_document = Document(
            title=file.filename,
            content=text_content,
            file_path=f"uploads/{user.id}/{file.filename}",
            file_size=file.size,
            content_type=file.content_type,
            is_public=is_public,
            created_by=user.id,
            updated_by=user.id
        )
        
        db_session.add(new_document)
        db_session.commit()
        db_session.refresh(new_document)
        
        # Store file (implementation depends on storage backend)
        await store_document_file(content, new_document.file_path)
        
        logger.info(f"Document {new_document.id} uploaded by user {user.email}")
        return DocumentResponse.from_document(new_document)
        
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
    is_public: bool = False,
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
```

## Testing Requirements

### Unit Tests
**File**: `backend/tests/unit/test_document_permissions.py`

```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import HTTPException, status
from onyx.server.documents.document import (
    get_documents,
    get_document,
    create_document,
    update_document,
    delete_document
)
from onyx.db.models import User, Document
from onyx.server.documents.models import DocumentCreate, DocumentUpdate

class TestDocumentPermissions:
    
    @pytest.fixture
    def mock_user(self):
        user = User()
        user.id = 1
        user.email = "test@example.com"
        return user
    
    @pytest.fixture
    def mock_document(self):
        doc = Document()
        doc.id = 1
        doc.title = "Test Document"
        doc.content = "Test content"
        doc.is_public = True
        doc.created_by = 1
        return doc
    
    @pytest.fixture
    def mock_db_session(self):
        session = MagicMock()
        return session
    
    @pytest.mark.asyncio
    async def test_get_documents_with_read_permission(self, mock_user, mock_document, mock_db_session):
        """Test document retrieval with read permission"""
        # Mock database query
        mock_db_session.query.return_value.offset.return_value.limit.return_value.all.return_value = [mock_document]
        
        with patch('onyx.server.documents.document.get_user_oauth_permission') as mock_permission:
            mock_permission.return_value = "read"
            
            documents = await get_documents(
                limit=100, 
                offset=0, 
                search=None,
                user=mock_user, 
                db_session=mock_db_session
            )
            
            assert len(documents) == 1
            assert documents[0].title == "Test Document"
    
    @pytest.mark.asyncio
    async def test_create_document_with_write_permission(self, mock_user, mock_db_session):
        """Test document creation with write permission"""
        document_data = DocumentCreate(
            title="New Document",
            content="New content",
            is_public=False
        )
        
        # Mock successful creation
        mock_db_session.add = MagicMock()
        mock_db_session.commit = MagicMock()
        mock_db_session.refresh = MagicMock()
        
        created_doc = await create_document(
            document_data=document_data,
            user=mock_user,
            db_session=mock_db_session
        )
        
        assert created_doc.title == "New Document"
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_document_owner_access(self, mock_user, mock_document, mock_db_session):
        """Test document update by owner"""
        mock_document.created_by = mock_user.id
        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_document
        
        with patch('onyx.server.documents.document.get_user_oauth_permission') as mock_permission:
            mock_permission.return_value = "write"
            
            update_data = DocumentUpdate(title="Updated Title")
            
            updated_doc = await update_document(
                document_id=1,
                document_data=update_data,
                user=mock_user,
                db_session=mock_db_session
            )
            
            assert updated_doc.title == "Updated Title"
    
    @pytest.mark.asyncio
    async def test_update_document_non_owner_denied(self, mock_user, mock_document, mock_db_session):
        """Test document update denied for non-owner"""
        mock_document.created_by = 999  # Different user
        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_document
        
        with patch('onyx.server.documents.document.get_user_oauth_permission') as mock_permission:
            mock_permission.return_value = "write"  # Not admin
            
            update_data = DocumentUpdate(title="Updated Title")
            
            with pytest.raises(HTTPException) as exc_info:
                await update_document(
                    document_id=1,
                    document_data=update_data,
                    user=mock_user,
                    db_session=mock_db_session
                )
            
            assert exc_info.value.status_code == 403
            assert "Can only update your own documents" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_delete_document_admin_access(self, mock_user, mock_document, mock_db_session):
        """Test document deletion by admin (any document)"""
        mock_document.created_by = 999  # Different user
        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_document
        
        with patch('onyx.server.documents.document.get_user_oauth_permission') as mock_permission:
            mock_permission.return_value = "admin"  # Admin can delete any document
            
            # Should not raise exception
            await delete_document(
                document_id=1,
                user=mock_user,
                db_session=mock_db_session
            )
            
            mock_db_session.delete.assert_called_once_with(mock_document)
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_private_document_access_denied(self, mock_user, mock_document, mock_db_session):
        """Test access denied for private document of another user"""
        mock_document.is_public = False
        mock_document.created_by = 999  # Different user
        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_document
        
        with patch('onyx.server.documents.document.get_user_oauth_permission') as mock_permission:
            mock_permission.return_value = "read"
            
            with pytest.raises(HTTPException) as exc_info:
                await get_document(
                    document_id=1,
                    user=mock_user,
                    db_session=mock_db_session
                )
            
            assert exc_info.value.status_code == 403
            assert "Access denied to private document" in exc_info.value.detail
```

### Integration Tests
**File**: `backend/tests/integration/test_document_api_permissions.py`

```python
import pytest
from fastapi.testclient import TestClient
from onyx.main import app
from onyx.db.models import User, OAuthPermission, Document
from tests.integration.test_utils import TestUser

class TestDocumentAPIPermissions:
    
    @pytest.fixture
    def client(self):
        return TestClient(app)
    
    @pytest.fixture
    def read_user(self, db_session):
        user = TestUser.create_test_user(email="read@test.com")
        permission = OAuthPermission(
            user_id=user.id,
            permission_level="read",
            okta_groups=["Onyx-Readers"]
        )
        db_session.add(permission)
        db_session.commit()
        return user
    
    @pytest.fixture
    def write_user(self, db_session):
        user = TestUser.create_test_user(email="write@test.com")
        permission = OAuthPermission(
            user_id=user.id,
            permission_level="write",
            okta_groups=["Onyx-Writers"]
        )
        db_session.add(permission)
        db_session.commit()
        return user
    
    @pytest.fixture
    def admin_user(self, db_session):
        user = TestUser.create_test_user(email="admin@test.com")
        permission = OAuthPermission(
            user_id=user.id,
            permission_level="admin",
            okta_groups=["Onyx-Admins"]
        )
        db_session.add(permission)
        db_session.commit()
        return user
    
    @pytest.fixture
    def test_document(self, db_session, write_user):
        doc = Document(
            title="Test Document",
            content="Test content",
            is_public=True,
            created_by=write_user.id
        )
        db_session.add(doc)
        db_session.commit()
        return doc
    
    def test_get_documents_read_permission(self, client, read_user):
        """Test GET /documents with read permission"""
        with TestUser.logged_in_user(read_user):
            response = client.get("/api/documents")
            assert response.status_code == 200
            assert isinstance(response.json(), list)
    
    def test_get_documents_no_permission(self, client):
        """Test GET /documents without proper authentication"""
        response = client.get("/api/documents")
        assert response.status_code == 401
    
    def test_create_document_write_permission(self, client, write_user):
        """Test POST /documents with write permission"""
        document_data = {
            "title": "New Document",
            "content": "New content",
            "is_public": False
        }
        
        with TestUser.logged_in_user(write_user):
            response = client.post("/api/documents", json=document_data)
            assert response.status_code == 201
            
            response_data = response.json()
            assert response_data["title"] == "New Document"
            assert response_data["content"] == "New content"
    
    def test_create_document_read_only_denied(self, client, read_user):
        """Test POST /documents denied with read-only permission"""
        document_data = {
            "title": "New Document",
            "content": "New content"
        }
        
        with TestUser.logged_in_user(read_user):
            response = client.post("/api/documents", json=document_data)
            assert response.status_code == 403
            
            error_data = response.json()
            assert "Insufficient permissions" in error_data["detail"]
    
    def test_update_document_owner(self, client, write_user, test_document):
        """Test PUT /documents/{id} by document owner"""
        update_data = {
            "title": "Updated Title",
            "content": "Updated content"
        }
        
        with TestUser.logged_in_user(write_user):
            response = client.put(f"/api/documents/{test_document.id}", json=update_data)
            assert response.status_code == 200
            
            response_data = response.json()
            assert response_data["title"] == "Updated Title"
    
    def test_update_document_non_owner_denied(self, client, write_user, test_document, db_session):
        """Test PUT /documents/{id} denied for non-owner"""
        # Create another write user
        other_user = TestUser.create_test_user(email="other@test.com")
        permission = OAuthPermission(
            user_id=other_user.id,
            permission_level="write",
            okta_groups=["Onyx-Writers"]
        )
        db_session.add(permission)
        db_session.commit()
        
        update_data = {"title": "Hacked Title"}
        
        with TestUser.logged_in_user(other_user):
            response = client.put(f"/api/documents/{test_document.id}", json=update_data)
            assert response.status_code == 403
            assert "Can only update your own documents" in response.json()["detail"]
    
    def test_update_document_admin_access(self, client, admin_user, test_document):
        """Test PUT /documents/{id} allowed for admin"""
        update_data = {"title": "Admin Updated Title"}
        
        with TestUser.logged_in_user(admin_user):
            response = client.put(f"/api/documents/{test_document.id}", json=update_data)
            assert response.status_code == 200
            
            response_data = response.json()
            assert response_data["title"] == "Admin Updated Title"
    
    def test_delete_document_owner(self, client, write_user, test_document):
        """Test DELETE /documents/{id} by document owner"""
        with TestUser.logged_in_user(write_user):
            response = client.delete(f"/api/documents/{test_document.id}")
            assert response.status_code == 204
    
    def test_delete_document_read_only_denied(self, client, read_user, test_document):
        """Test DELETE /documents/{id} denied with read-only permission"""
        with TestUser.logged_in_user(read_user):
            response = client.delete(f"/api/documents/{test_document.id}")
            assert response.status_code == 403
    
    def test_search_documents_permission_filtering(self, client, read_user, write_user, db_session):
        """Test that search results are filtered by permission level"""
        # Create public and private documents
        public_doc = Document(
            title="Public Document",
            content="Public content",
            is_public=True,
            created_by=write_user.id
        )
        private_doc = Document(
            title="Private Document", 
            content="Private content",
            is_public=False,
            created_by=write_user.id
        )
        db_session.add_all([public_doc, private_doc])
        db_session.commit()
        
        search_data = {"query": "Document"}
        
        # Read user should only see public document
        with TestUser.logged_in_user(read_user):
            response = client.post("/api/documents/search", json=search_data)
            assert response.status_code == 200
            
            documents = response.json()
            titles = [doc["title"] for doc in documents]
            assert "Public Document" in titles
            assert "Private Document" not in titles
        
        # Write user should see both (as owner)
        with TestUser.logged_in_user(write_user):
            response = client.post("/api/documents/search", json=search_data)
            assert response.status_code == 200
            
            documents = response.json()
            titles = [doc["title"] for doc in documents]
            assert "Public Document" in titles
            assert "Private Document" in titles
    
    def test_file_upload_write_permission(self, client, write_user):
        """Test file upload with write permission"""
        file_content = b"Test file content"
        
        with TestUser.logged_in_user(write_user):
            response = client.post(
                "/api/documents/upload",
                files={"file": ("test.txt", file_content, "text/plain")},
                data={"is_public": "false"}
            )
            assert response.status_code == 201
            
            response_data = response.json()
            assert response_data["title"] == "test.txt"
    
    def test_file_upload_read_only_denied(self, client, read_user):
        """Test file upload denied with read-only permission"""
        file_content = b"Test file content"
        
        with TestUser.logged_in_user(read_user):
            response = client.post(
                "/api/documents/upload",
                files={"file": ("test.txt", file_content, "text/plain")}
            )
            assert response.status_code == 403
```

## Performance Requirements

- **Response Time**: Document operations < 200ms (95th percentile)
- **Throughput**: Support 500+ concurrent document requests
- **Permission Check Overhead**: < 5ms additional latency per request
- **Memory Usage**: < 10MB additional memory for permission caching

### Performance Tests
**File**: `backend/tests/performance/test_document_api_performance.py`

```python
import pytest
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from onyx.main import app

class TestDocumentAPIPerformance:
    
    @pytest.fixture
    def client(self):
        return TestClient(app)
    
    def test_get_documents_performance(self, client, write_user):
        """Test GET /documents performance with permission checks"""
        with TestUser.logged_in_user(write_user):
            # Warm up
            client.get("/api/documents")
            
            # Measure performance
            start_time = time.perf_counter()
            
            for _ in range(100):
                response = client.get("/api/documents")
                assert response.status_code == 200
            
            end_time = time.perf_counter()
            avg_response_time = (end_time - start_time) / 100
            
            # Should average < 200ms per request
            assert avg_response_time < 0.2, f"Average response time {avg_response_time:.3f}s exceeds 200ms"
    
    def test_concurrent_document_access(self, client, write_user):
        """Test concurrent document access performance"""
        def make_request():
            with TestUser.logged_in_user(write_user):
                return client.get("/api/documents")
        
        # Run 100 concurrent requests
        start_time = time.perf_counter()
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(make_request) for _ in range(100)]
            results = [future.result() for future in futures]
        
        end_time = time.perf_counter()
        
        # All should succeed
        successful = sum(1 for r in results if r.status_code == 200)
        assert successful == 100
        
        # Should complete within 5 seconds
        total_time = end_time - start_time
        assert total_time < 5.0, f"100 concurrent requests took {total_time:.2f}s"
    
    def test_permission_check_overhead(self, client, write_user):
        """Measure permission check overhead"""
        # TODO: Compare response times with and without permission checks
        # This would require a feature flag to disable permission checks
        pass
```

## Security Considerations

1. **Access Control**: Proper enforcement of document ownership and visibility rules
2. **Data Leakage Prevention**: Read users cannot access private documents of other users
3. **Permission Escalation**: Write users cannot modify admin-created documents unless they're admin
4. **Audit Trail**: All permission-denied access attempts are logged
5. **Input Validation**: All document data is validated before processing

## Deployment Checklist

### Pre-deployment
- [ ] All unit tests pass (target: 95% coverage)
- [ ] Integration tests pass in staging environment
- [ ] Performance tests meet latency requirements
- [ ] Security review completed for permission logic
- [ ] Test with all permission levels (read, write, admin)

### Deployment Steps
1. **Deploy Code**: Deploy updated document router with permission dependencies
2. **Verify Endpoints**: Test all document endpoints with different permission levels
3. **Monitor Performance**: Check response times and error rates
4. **Validate Permissions**: Confirm proper access control enforcement
5. **Check Logs**: Monitor for permission-related errors

### Post-deployment
- [ ] Monitor document API response times
- [ ] Verify permission enforcement is working correctly
- [ ] Check for any increases in 403 error rates
- [ ] Validate audit logs are capturing permission denials
- [ ] Test document operations with different user types

## Rollback Plan

### Immediate Rollback (< 5 minutes)
1. Set feature flag `ENABLE_DOCUMENT_PERMISSIONS=false`
2. Restart application servers
3. Verify document operations work without permission checks

### Full Rollback (< 15 minutes)
1. Deploy previous version of document router
2. Restart services
3. Run smoke tests on document endpoints

## Definition of Done

- [ ] ✅ All document endpoints protected with appropriate permission levels
- [ ] ✅ GET operations require read permission
- [ ] ✅ POST/PUT/DELETE operations require write permission
- [ ] ✅ Proper 403 responses for insufficient permissions
- [ ] ✅ Document ownership and visibility rules enforced
- [ ] ✅ Integration tests covering all permission scenarios
- [ ] ✅ Performance tests showing acceptable response times
- [ ] ✅ Security review completed and approved
- [ ] ✅ Audit logging implemented for access denials
- [ ] ✅ Admin override functionality working correctly
- [ ] ✅ File upload protection implemented
- [ ] ✅ Search results properly filtered by permissions
- [ ] ✅ Documentation updated for new permission requirements
- [ ] ✅ Monitoring and alerting configured

## Risk Assessment

**High Risk**: Breaking existing document access for authenticated users  
**Mitigation**: Thorough testing, feature flags, gradual rollout

**Medium Risk**: Performance degradation from permission checks  
**Mitigation**: Caching, performance monitoring, load testing

**Low Risk**: Permission logic bugs  
**Mitigation**: Comprehensive unit tests, security review
