from typing import Optional, Any
from pydantic import BaseModel, ConfigDict
from datetime import datetime

class ColumnMappingSuggestion(BaseModel):
    target_field: str
    source_column: Optional[str] = None
    confidence: float
    explanation: str
    required_for: list[str]

class DataProfile(BaseModel):
    total_rows: int
    total_columns: int
    duplicate_rows: int
    column_types: dict[str, str]
    missing_values: dict[str, int]
    sample_rows: list[dict[str, Any]]

class DatasetUploadResponse(BaseModel):
    dataset_id: str
    filename: str
    row_count: int
    column_count: int
    compatibility_status: str
    compatibility_reasons: list[str]
    suggested_mapping: dict[str, Optional[str]]
    mapping_details: list[ColumnMappingSuggestion]
    data_profile: DataProfile

class DatasetConfirmMappingRequest(BaseModel):
    mapping: dict[str, str]  # target_field -> source_column

class DatasetItem(BaseModel):
    id: str
    filename: str
    file_size_bytes: int
    row_count: int
    column_count: int
    compatibility_status: str
    compatibility_reasons: list[str]
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class DatasetDetailResponse(DatasetItem):
    column_mapping: dict[str, str]
    data_profile: DataProfile
