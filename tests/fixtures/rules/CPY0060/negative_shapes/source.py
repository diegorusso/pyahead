from typing import TypedDict

options: dict[str, object] = {}

TypedDict("Record", None, value=int)
TypedDict("ExpandedNone", None, **options)
TypedDict("ExpandedOmitted", **options)
