"""Focused tests for the Stable 1.0 public-observation transport."""

from __future__ import annotations

import hashlib
import unittest
from io import BytesIO
from typing import Callable
from unittest import mock

from cryptad_certification.engines import stable_1_0_public_observation as public_observation

COMMIT = "a" * 40


class _FakeHttpResponse:
    def __init__(
        self,
        status: int,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self._body = BytesIO(body)
        self._headers = headers or {}
        self.read_sizes: list[int] = []

    def getheader(self, name: str) -> str | None:
        return self._headers.get(name)

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self._body.read(size)


def _scripted_connections(
    responses: list[_FakeHttpResponse],
) -> tuple[Callable[..., mock.Mock], list[dict[str, str]]]:
    requests: list[dict[str, str]] = []

    def factory(*_args: object, **_kwargs: object) -> mock.Mock:
        if not responses:
            raise AssertionError("unexpected HTTPS connection")
        connection = mock.Mock()
        connection.getresponse.return_value = responses.pop(0)

        def request(
            _method: str,
            _path: str,
            *,
            headers: dict[str, str],
        ) -> None:
            requests.append(dict(headers))

        connection.request.side_effect = request
        return connection

    return factory, requests


class StablePublicObservationTransportTests(unittest.TestCase):
    def test_redirect_revalidates_destination_and_rejects_private_address(self) -> None:
        factory, _requests = _scripted_connections(
            [
                _FakeHttpResponse(
                    302,
                    headers={"Location": "https://127.0.0.1/private"},
                )
            ]
        )

        def addresses(host: str, _port: int) -> tuple[str, ...]:
            if host == "public.crypta.network":
                return ("8.8.8.8",)
            raise public_observation.PublicObservationTransportError(
                "public-host-resolution-not-global"
            )

        with mock.patch.object(
            public_observation, "_global_addresses", side_effect=addresses
        ), mock.patch.object(
            public_observation, "_PinnedHTTPSConnection", side_effect=factory
        ):
            with self.assertRaisesRegex(
                public_observation.PublicObservationTransportError,
                "not-global",
            ):
                public_observation.PublicObservationTransport().bounded_digest(
                    "https://public.crypta.network/object"
                )

    def test_global_resolution_rejects_any_private_answer(self) -> None:
        rows = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("10.0.0.8", 443)),
        ]

        with mock.patch.object(
            public_observation.socket, "getaddrinfo", return_value=rows
        ):
            with self.assertRaisesRegex(
                public_observation.PublicObservationTransportError,
                "not-global",
            ):
                public_observation._global_addresses(  # noqa: SLF001
                    "public.crypta.network", 443
                )

    def test_pinned_connection_rejects_a_different_connected_peer(self) -> None:
        raw = mock.Mock()
        raw.getpeername.return_value = ("1.1.1.1", 443)
        connection = public_observation._PinnedHTTPSConnection(  # noqa: SLF001
            "public.crypta.network", "8.8.8.8", 443, 1.0
        )

        with mock.patch.object(
            public_observation.socket, "create_connection", return_value=raw
        ):
            with self.assertRaisesRegex(OSError, "differs from pinned"):
                connection.connect()

        raw.close.assert_called_once_with()

    def test_api_json_rejects_redirects_and_bounds_the_response(self) -> None:
        factory, _requests = _scripted_connections(
            [_FakeHttpResponse(302, headers={"Location": "https://api.github.com/other"})]
        )
        transport = public_observation.PublicObservationTransport()

        with mock.patch.object(
            public_observation, "_global_addresses", return_value=("8.8.8.8",)
        ), mock.patch.object(
            public_observation, "_PinnedHTTPSConnection", side_effect=factory
        ):
            with self.assertRaisesRegex(
                public_observation.PublicObservationTransportError,
                "redirect-forbidden",
            ):
                transport.json_document(
                    "https://api.github.com/repos/crypta-network/cryptad",
                    headers={"Authorization": "Bearer protected"},
                )

        factory, _requests = _scripted_connections(
            [_FakeHttpResponse(200, b"{}x", {"Content-Length": "3"})]
        )
        with mock.patch.object(
            public_observation, "_global_addresses", return_value=("8.8.8.8",)
        ), mock.patch.object(
            public_observation, "_PinnedHTTPSConnection", side_effect=factory
        ):
            with self.assertRaisesRegex(
                public_observation.PublicObservationTransportError,
                "too-large",
            ):
                transport.json_document(
                    "https://api.github.com/repos/crypta-network/cryptad",
                    maximum_bytes=2,
                )

    def test_public_redirect_strips_credentials_and_streams_exact_bytes(self) -> None:
        body = b"exact public bytes"
        final_response = _FakeHttpResponse(200, body, {"Content-Length": str(len(body))})
        factory, requests = _scripted_connections(
            [
                _FakeHttpResponse(
                    302,
                    headers={"Location": "https://objects.crypta.network/final"},
                ),
                final_response,
            ]
        )

        with mock.patch.object(
            public_observation, "_global_addresses", return_value=("8.8.8.8",)
        ), mock.patch.object(
            public_observation, "_PinnedHTTPSConnection", side_effect=factory
        ):
            observed = public_observation.PublicObservationTransport().exact_digest(
                "https://public.crypta.network/object",
                len(body),
                headers={
                    "Authorization": "Bearer must-not-cross",
                    "Accept": "application/octet-stream",
                },
            )

        self.assertEqual(len(body), observed.size)
        self.assertEqual(
            "sha256:" + hashlib.sha256(body).hexdigest(),
            observed.digest,
        )
        self.assertIn("Authorization", requests[0])
        self.assertNotIn("Authorization", requests[1])
        self.assertTrue(final_response.read_sizes)
        self.assertTrue(all(0 < size <= 64 * 1024 for size in final_response.read_sizes))

    def test_public_redirect_rejects_a_second_hop(self) -> None:
        factory, _requests = _scripted_connections(
            [
                _FakeHttpResponse(
                    302,
                    headers={"Location": "https://objects.crypta.network/first"},
                ),
                _FakeHttpResponse(
                    302,
                    headers={"Location": "https://objects.crypta.network/second"},
                ),
            ]
        )

        with mock.patch.object(
            public_observation, "_global_addresses", return_value=("8.8.8.8",)
        ), mock.patch.object(
            public_observation, "_PinnedHTTPSConnection", side_effect=factory
        ):
            with self.assertRaisesRegex(
                public_observation.PublicObservationTransportError,
                "redirect-forbidden",
            ):
                public_observation.PublicObservationTransport().bounded_digest(
                    "https://public.crypta.network/object"
                )

    def test_exact_stream_rejects_declared_and_chunked_overflow(self) -> None:
        transport = public_observation.PublicObservationTransport()
        for response in (
            _FakeHttpResponse(200, b"", {"Content-Length": "4"}),
            _FakeHttpResponse(200, b"four"),
        ):
            with self.subTest(headers=response._headers):
                factory, _requests = _scripted_connections([response])
                with mock.patch.object(
                    public_observation,
                    "_global_addresses",
                    return_value=("8.8.8.8",),
                ), mock.patch.object(
                    public_observation,
                    "_PinnedHTTPSConnection",
                    side_effect=factory,
                ):
                    with self.assertRaises(
                        public_observation.PublicObservationTransportError
                    ):
                        transport.exact_digest(
                            "https://public.crypta.network/object",
                            3,
                        )

    def test_release_identity_rejects_retitled_or_prerelease_state(self) -> None:
        body = "Stable notes"
        notes_digest = "sha256:" + hashlib.sha256(body.encode()).hexdigest()
        receipt = {
            "releaseId": 3,
            "publicUrl": "https://github.com/crypta-network/cryptad/releases/tag/v3",
            "releaseNotesDigest": notes_digest,
        }
        release = {
            "id": 3,
            "html_url": receipt["publicUrl"],
            "name": "Cryptad Stable 1.0 (v3)",
            "tag_name": "v3",
            "target_commitish": COMMIT,
            "draft": False,
            "prerelease": False,
            "body": body,
        }
        expected = public_observation.github_release_identity(
            release,
            receipt,
            build="3",
            commit=COMMIT,
        )
        self.assertEqual("Cryptad Stable 1.0 (v3)", expected["name"])
        for field, mutation in (
            ("name", "Retitled"),
            ("prerelease", True),
            ("prerelease", 0),
            ("draft", 0),
        ):
            with self.subTest(field=field):
                wrong = dict(release)
                wrong[field] = mutation
                with self.assertRaisesRegex(
                    public_observation.PublicObservationTransportError,
                    "identity-differs",
                ):
                    public_observation.github_release_identity(
                        wrong,
                        receipt,
                        build="3",
                        commit=COMMIT,
                    )

    def test_catalog_signature_uri_uses_the_canonical_detached_sibling(self) -> None:
        self.assertEqual(
            "https://catalog.crypta.network/stable/cryptad-app-catalog.signature",
            public_observation.catalog_signature_uri(
                "https://catalog.crypta.network/stable/cryptad-app-catalog.properties"
            ),
        )
        self.assertEqual(
            "https://catalog.crypta.network/stable/first-party-catalog.sig",
            public_observation.catalog_signature_uri(
                "https://catalog.crypta.network/stable/first-party-catalog.properties"
            ),
        )
        with self.assertRaisesRegex(
            public_observation.PublicObservationTransportError,
            "unsupported",
        ):
            public_observation.catalog_signature_uri(
                "https://catalog.crypta.network/stable/catalog.json"
            )

    def test_annotated_tag_identity_rejects_substituted_embedded_name(self) -> None:
        tag_sha = "b" * 40
        reference = {
            "ref": "refs/tags/v3",
            "object": {"type": "tag", "sha": tag_sha},
        }
        tag = {
            "sha": tag_sha,
            "tag": "v3",
            "object": {"type": "commit", "sha": COMMIT},
        }

        observed = public_observation.github_annotated_tag_identity(
            reference,
            tag,
            build="3",
            commit=COMMIT,
        )

        self.assertEqual(
            {
                "name": "v3",
                "targetCommit": COMMIT,
                "annotated": True,
                "status": "observed-exact",
            },
            observed,
        )
        mutations = (
            (reference, {**tag, "tag": "v999"}),
            ({**reference, "ref": "refs/tags/v999"}, tag),
            (
                {**reference, "object": {"type": "commit", "sha": tag_sha}},
                tag,
            ),
            (reference, {**tag, "sha": "c" * 40}),
            (
                reference,
                {**tag, "object": {"type": "commit", "sha": "d" * 40}},
            ),
        )
        for wrong_reference, wrong_tag in mutations:
            with self.subTest(reference=wrong_reference, tag=wrong_tag):
                with self.assertRaisesRegex(
                    public_observation.PublicObservationTransportError,
                    "github-annotated-tag-identity-differs",
                ):
                    public_observation.github_annotated_tag_identity(
                        wrong_reference,
                        wrong_tag,
                        build="3",
                        commit=COMMIT,
                    )

    def test_release_asset_metadata_rejects_duplicates_and_wrong_size(self) -> None:
        planned = [
            {
                "name": "product.tar.gz",
                "sizeBytes": 4,
                "digest": "sha256:" + "1" * 64,
            }
        ]
        exact = {
            "name": "product.tar.gz",
            "state": "uploaded",
            "size": 4,
            "digest": "sha256:" + "1" * 64,
            "browser_download_url": "https://github.com/download/product.tar.gz",
        }
        self.assertEqual(
            {"product.tar.gz": exact},
            public_observation.github_release_assets([exact], planned),
        )
        for rows in ([exact, exact], [{**exact, "size": 5}]):
            with self.subTest(rows=rows):
                with self.assertRaises(
                    public_observation.PublicObservationTransportError
                ):
                    public_observation.github_release_assets(rows, planned)
