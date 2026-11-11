
from datetime import datetime, timezone

from backend.app.security.versioned_reporting import (
    verify_versioned_report
)


DEFAULT_REVIEW_DAYS = 90
MAX_REVIEW_DAYS = 36500


class ReportRetentionError(Exception):
    """A safe retention assessment could not be made."""


def assess_report_retention(
    envelope,
    key_directory,
    as_of=None,
    review_after_days=DEFAULT_REVIEW_DAYS
):
    """
    Assess retention for an authenticated report.

    Steps:
      1. Validate the review policy.
      2. Verify the report's HMAC.
      3. Read its authenticated creation timestamp.
      4. Recommend retain or manual review.

    Never deletes, moves, archives or rewrites
    reports or protected signing keys.
    """

    try:
        # Validate the policy threshold.
        # bool is deliberately not accepted as int.
        if (
            type(review_after_days) is not int
            or not 1 <= review_after_days <= MAX_REVIEW_DAYS
        ):
            raise ValueError("Invalid review policy")

        # Use an explicit test time or current UTC.
        if as_of is None:
            as_of = datetime.now(timezone.utc)

        if (
            not isinstance(as_of, datetime)
            or as_of.tzinfo is None
            or as_of.utcoffset() is None
        ):
            raise ValueError("Invalid review time")

        review_time = as_of.astimezone(timezone.utc)

        # Authenticate BEFORE using report metadata.
        verified = verify_versioned_report(
            envelope=envelope,
            key_directory=key_directory
        )

        if type(verified) is not dict:
            raise ValueError("Invalid verified report")

        created_text = verified.get(
            "generated_at_utc"
        )

        if type(created_text) is not str:
            raise ValueError("Missing creation timestamp")

        # fromisoformat supports UTC offsets.
        # Explicitly support trailing Z as well.
        created_time = datetime.fromisoformat(
            created_text.replace("Z", "+00:00")
        )

        if (
            created_time.tzinfo is None
            or created_time.utcoffset() is None
        ):
            raise ValueError("Timezone missing")

        created_time = created_time.astimezone(
            timezone.utc
        )

        # The key ID comes from the authenticated
        # envelope, not unauthenticated input.
        key_id = envelope["key_id"]

        if created_time > review_time:
            decision = "timestamp_review"
            age_days = 0
            recommendation = (
                "Review the future-dated report timestamp. "
                "Preserve the report and its signing key."
            )

        else:
            age_days = (
                review_time - created_time
            ).days

            if age_days >= review_after_days:
                decision = "archive_review"
                recommendation = (
                    "Request an authorized retention review. "
                    "Preserve the report and its signing key."
                )

            else:
                decision = "retain"
                recommendation = (
                    "Keep the authenticated report in "
                    "approved active storage."
                )

        return {
            "decision": decision,
            "authenticated": True,
            "key_id": key_id,
            "age_days": age_days,
            "review_after_days": review_after_days,
            "manual_review_required": (
                decision != "retain"
            ),
            "recommended_action": recommendation,
            "automatic_deletion_allowed": False,
            "automatic_archival_performed": False,
            "automatic_repairs_performed": False
        }

    except Exception:
        raise ReportRetentionError(
            "Report retention assessment failed"
        ) from None
