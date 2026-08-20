"""with_message() must carry every field, including ones added later.

Rebuilding the exception by hand at each call site is what dropped error_info
and www_authenticate when two branches were merged; this is the guard against
that happening again as fields are added.
"""

from mcp_for_powerbi.server import PowerBIAPIError

DETAILS = {"DetailsMessage": "d", "AnalysisServicesErrorCode": "3242524690"}


def make():
    return PowerBIAPIError("original", 401, "SomeCode", dict(DETAILS), "TokenExpired", 'Bearer error="x"')


def test_replaces_only_the_message():
    original = make()
    clone = original.with_message("original\n\nextra context")
    assert str(clone) == "original\n\nextra context"
    assert str(original) == "original", "the original must be left alone"
    assert clone is not original


def test_carries_every_known_field():
    original = make()
    clone = original.with_message("x")
    assert clone.status_code == 401
    assert clone.error_code == "SomeCode"
    assert clone.details == DETAILS
    assert clone.error_info == "TokenExpired"
    assert clone.www_authenticate == 'Bearer error="x"'
    assert isinstance(clone, PowerBIAPIError)


def test_carries_fields_added_after_construction():
    """The point of the helper: a new field needs no change at any call site."""
    original = make()
    original.some_future_field = "carried"
    assert getattr(original.with_message("x"), "some_future_field", None) == "carried"


def test_predicates_survive_the_copy():
    assert make().with_message("x").is_token_rejection() is True


def test_details_are_shared_not_deep_copied():
    """Documented shallow behaviour, asserted so a change to it is deliberate."""
    original = make()
    assert original.with_message("x").details is original.details
