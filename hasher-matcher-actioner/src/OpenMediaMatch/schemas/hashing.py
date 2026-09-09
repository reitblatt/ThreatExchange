# Copyright (c) Meta Platforms, Inc. and affiliates.

from typing import Optional

from flask_openapi3 import FileStorage
from pydantic import BaseModel, ConfigDict, Field


class HashRequest(BaseModel):
    """Request schema for hashing content from URL."""

    url: str = Field(..., description="URL to the media content to hash")
    content_type: Optional[str] = Field(
        None, description="Content type (photo, video, etc.)"
    )
    types: Optional[str] = Field(
        None, description="Comma-separated list of signal types to generate"
    )


class HashResponse(BaseModel):
    """Response schema for hash generation."""

    model_config = ConfigDict(extra="allow")


class HashPostRequest(BaseModel):
    """
    multipart/form-data body for ``POST /h/hash``.

    A single file is uploaded under a field named for its content type. ``photo``
    and ``video`` are the built-in content types and are modelled explicitly here;
    the endpoint also accepts a file under the name of any other enabled content
    type.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    photo: Optional[FileStorage] = Field(None, description="An image file to hash")
    video: Optional[FileStorage] = Field(None, description="A video file to hash")
