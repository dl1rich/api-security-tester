"""File upload and URL fetching endpoints."""

from fastapi import APIRouter, File, UploadFile, HTTPException, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
from typing import Optional
import httpx
import yaml
import json
import sys
import logging
from pathlib import Path

from utils.config import settings
from parser.openapi_parser import OpenAPIParser
from utils.dependencies import get_parser

logger = logging.getLogger(__name__)
router = APIRouter()

# Increase recursion limit for complex OpenAPI specs
sys.setrecursionlimit(5000)


class URLUploadRequest(BaseModel):
    """Request model for URL-based upload."""
    url: HttpUrl
    auth_header: Optional[str] = None


class UploadResponse(BaseModel):
    """Response model for file/URL upload."""
    success: bool
    message: str
    spec_id: str
    spec_info: dict


@router.post("/upload/file", response_model=UploadResponse)
async def upload_spec_file(file: UploadFile = File(...)):
    """Upload OpenAPI/Swagger specification file."""
    try:
        # Validate file size
        contents = await file.read()
        if len(contents) > settings.max_file_size:
            raise HTTPException(status_code=413, detail="File too large")
        
        # Validate file type
        if not file.filename or not any(file.filename.endswith(ext) for ext in ['.json', '.yaml', '.yml']):
            raise HTTPException(status_code=400, detail="Invalid file type. Only JSON and YAML files are allowed")
        
        # Parse content
        try:
            if file.filename.endswith('.json'):
                spec_data = json.loads(contents.decode('utf-8'))
            else:  # YAML
                spec_data = yaml.safe_load(contents.decode('utf-8'))
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise HTTPException(status_code=400, detail=f"Invalid file format: {str(e)}")
        
        logger.info(f"Parsing {file.filename} ({len(contents)} bytes)")
        
        # Parse with OpenAPI parser (use shared instance)
        parser = get_parser()
        parsed_spec = parser.parse_specification(spec_data)
        
        logger.info(f"Successfully parsed spec: {parsed_spec.title} with {len(parsed_spec.endpoints)} endpoints")
        
        return UploadResponse(
            success=True,
            message="File uploaded and parsed successfully",
            spec_id=parsed_spec.id,
            spec_info={
                "title": parsed_spec.title,
                "version": parsed_spec.version,
                "endpoint_count": len(parsed_spec.endpoints),
                "auth_methods": list(parsed_spec.auth_methods.keys()),
                "spec_version": parsed_spec.spec_version
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")


@router.post("/upload/url", response_model=UploadResponse)
async def upload_spec_url(request: URLUploadRequest):
    """Fetch OpenAPI/Swagger specification from URL."""
    try:
        headers = {}
        if request.auth_header:
            headers["Authorization"] = request.auth_header
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(str(request.url), headers=headers)
            response.raise_for_status()
            
        # Try to parse as JSON first, then YAML
        try:
            spec_data = response.json()
        except json.JSONDecodeError:
            try:
                spec_data = yaml.safe_load(response.text)
            except yaml.YAMLError as e:
                raise HTTPException(status_code=400, detail=f"Invalid specification format: {str(e)}")
        
        # Parse with OpenAPI parser
        parser = OpenAPIParser()
        parsed_spec = parser.parse_specification(spec_data)
        
        return UploadResponse(
            success=True,
            message="URL fetched and parsed successfully",
            spec_id=parsed_spec.id,
            spec_info={
                "title": parsed_spec.title,
                "version": parsed_spec.version,
                "endpoint_count": len(parsed_spec.endpoints),
                "auth_methods": list(parsed_spec.auth_methods.keys()),
                "spec_version": parsed_spec.spec_version,
                "source_url": str(request.url)
            }
        )
        
    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=f"Error fetching URL: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing URL: {str(e)}")


@router.get("/upload/validate/{spec_id}")
async def validate_specification(spec_id: str):
    """Validate a previously uploaded specification."""
    try:
        parser = get_parser()
        spec = parser.get_specification(spec_id)
        
        if not spec:
            raise HTTPException(status_code=404, detail="Specification not found")
        
        validation_result = parser.validate_specification(spec)
        
        return {
            "success": True,
            "spec_id": spec_id,
            "validation": validation_result,
            "ready_for_testing": validation_result.get("is_valid", False)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error validating specification: {str(e)}")