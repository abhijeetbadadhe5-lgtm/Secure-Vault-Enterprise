

from backend.app.security.kek_config import (
    validate_kek_id
)

from backend.app.security.key_wrapping import (
    check_key,
    wrap_dek,
    unwrap_dek
)


class KEKRegistry:
    """
    Store multiple KEKs in memory, indexed by key ID.

    This practice registry does not save KEKs to disk.
    """

    def __init__(self):
        self._keys = {}

    def register_key(self, key_id, kek):
        """
        Register a KEK under a unique identifier.

        An existing key ID cannot be replaced.
        """

        validate_kek_id(key_id)
        check_key(kek, "KEK")

        if key_id in self._keys:
            raise ValueError(
                "KEK ID is already registered"
            )

        self._keys[key_id] = kek

    def get_key(self, key_id):
        """
        Find the KEK matching the provided identifier.

        Unknown keys are rejected rather than replaced.
        """

        validate_kek_id(key_id)

        if key_id not in self._keys:
            raise KeyError(
                "Requested KEK ID is not available"
            )

        return self._keys[key_id]

    def wrap_document_key(
        self,
        dek,
        owner_user_id,
        storage_id,
        key_id
    ):
        """
        Wrap a DEK and record the KEK identifier.
        """

        kek = self.get_key(key_id)

        wrapped = wrap_dek(
            dek,
            kek,
            owner_user_id,
            storage_id
        )

        return {
            "key_id": key_id,
            "nonce": wrapped["nonce"],
            "wrapped_dek": wrapped["wrapped_dek"]
        }

    def unwrap_document_key(
        self,
        wrapped_record,
        owner_user_id,
        storage_id
    ):
        """
        Recover a DEK using the correct registered KEK.
        """

        if not isinstance(wrapped_record, dict):
            raise ValueError(
                "Wrapped key record must be a dictionary"
            )

        required_fields = {
            "key_id",
            "nonce",
            "wrapped_dek"
        }

        if not required_fields.issubset(
            wrapped_record
        ):
            raise ValueError(
                "Wrapped key record is incomplete"
            )

        key_id = wrapped_record["key_id"]

        kek = self.get_key(key_id)

        return unwrap_dek(
            wrapped_record["wrapped_dek"],
            wrapped_record["nonce"],
            kek,
            owner_user_id,
            storage_id
        )
