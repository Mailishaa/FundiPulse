"""End-to-end tests for organizations, memberships and their authorisation.

Real HTTP, real database, real constraints. The security assertions are the
point of this module, so they are written as security properties rather than
status codes wherever possible: a caller from ``Organization A`` must not be able
to read ``Organization B`` at all, an owner must not be able to demote themselves
out of the last ownership of a company, and a member's email address must never
appear in the roster.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.api.routes import organizations as organizations_routes
from app.core.constants import MembershipStatus, OrganizationRole, UserRole
from app.db.models.catalogue import County
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.worker import WorkerProfile
from app.schemas.organizations import MembershipResponse

pytestmark = [pytest.mark.api, pytest.mark.integration]


@pytest.fixture(autouse=True)
def _mount_organization_routes(app):
    """Mount the organization routers for this module.

    ``app/api/router.py`` belongs to another agent, so the domain is mounted here
    instead of there. The mount is conditional and disappears once the routers
    are registered in the application: it checks the OpenAPI paths, because a
    lazily included router is not visible on ``app.routes``.
    """
    if "/organizations" not in app.openapi()["paths"]:
        app.include_router(organizations_routes.router)
        app.include_router(organizations_routes.admin_router)
        app.openapi_schema = None  # the check above cached a schema without them
    return app


# --------------------------------------------------------------------------- #
# Fixtures and helpers                                                        #
# --------------------------------------------------------------------------- #
@pytest.fixture
def owner(make_user, auth_headers) -> dict:
    """An employer account that owns the company it creates."""
    user = make_user(role=UserRole.EMPLOYER)
    return {"user": user, "headers": auth_headers(user)}


@pytest.fixture
def other_owner(make_user, auth_headers) -> dict:
    """A second employer account with no relationship to the first company."""
    user = make_user(role=UserRole.EMPLOYER)
    return {"user": user, "headers": auth_headers(user)}


@pytest.fixture
def county(db_session) -> County:
    """One catalogue county. The suite does not seed the catalogues."""
    row = County(code="NAKURU", name="Nakuru")
    db_session.add(row)
    db_session.flush()
    return row


@pytest.fixture
def company(client, owner, county) -> dict:
    """A live company with contact details and a verified-code county code."""
    response = client.post(
        "/organizations",
        headers=owner["headers"],
        json={
            "name": "Nakuru Build Co",
            "description": "Civil and structural works in Nakuru county.",
            "industry": "Construction",
            "website_url": "https://nakuru-build.example",
            "location": "Nakuru town",
            "county_code": "NAKURU",
            "contact_email": "hello@nakuru-build.example",
            "contact_phone": "+254 712 345 678",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def _org_id(client, headers, name: str, **extra) -> uuid.UUID:
    response = client.post("/organizations", headers=headers, json={"name": name, **extra})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["data"]["id"])


def _add_member(client, headers, organization_id, **payload):
    return client.post(f"/organizations/{organization_id}/members", headers=headers, json=payload)


def _member(client, headers, organization_id, user, role="MEMBER", **extra) -> dict:
    response = _add_member(
        client, headers, organization_id, user_id=str(user.id), role=role, **extra
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


# --------------------------------------------------------------------------- #
# Creation                                                                    #
# --------------------------------------------------------------------------- #
class TestCreation:
    def test_creates_a_company_with_the_caller_as_owner(self, client, owner) -> None:
        response = client.post(
            "/organizations",
            headers=owner["headers"],
            json={"name": "Mombasa Marine Works", "industry": "Marine construction"},
        )
        assert response.status_code == 201, response.text
        data = response.json()["data"]
        assert data["name"] == "Mombasa Marine Works"
        assert data["slug"] == "mombasa-marine-works"
        assert data["is_active"] is True
        # Never self-asserted: the platform mark starts false and no request field
        # exists that could set it.
        assert data["is_verified"] is False

        mine = client.get(f"/organizations/{data['id']}/me", headers=owner["headers"])
        assert mine.status_code == 200
        assert mine.json()["data"]["role"] == OrganizationRole.OWNER.value
        assert mine.json()["data"]["status"] == MembershipStatus.ACTIVE.value

    def test_response_uses_the_envelope(self, client, owner) -> None:
        response = client.post(
            "/organizations", headers=owner["headers"], json={"name": "Envelope Ltd"}
        )
        body = response.json()
        assert set(body) == {"data", "meta"}
        assert body["meta"]["request_id"]

    def test_a_worker_account_may_not_register_a_company(self, client, make_user, auth_headers):
        worker = make_user()
        response = client.post(
            "/organizations", headers=auth_headers(worker), json={"name": "Unauthorised Ltd"}
        )
        assert response.status_code == 403

    def test_requires_authentication(self, client) -> None:
        assert client.post("/organizations", json={"name": "Anonymous Ltd"}).status_code == 401

    def test_rejects_a_stray_role_or_verification_field(self, client, owner) -> None:
        for payload in (
            {"name": "Mass Assignment Ltd", "is_verified": True},
            {"name": "Mass Assignment Ltd", "role": "ADMIN"},
        ):
            response = client.post("/organizations", headers=owner["headers"], json=payload)
            assert response.status_code == 422, response.text

    def test_rejects_a_bad_website_or_phone(self, client, owner) -> None:
        for payload in (
            {"name": "Bad Website Ltd", "website_url": "javascript:alert(1)"},
            {"name": "Bad Phone Ltd", "contact_phone": "0712345"},
        ):
            response = client.post("/organizations", headers=owner["headers"], json=payload)
            assert response.status_code == 422, response.text

    def test_normalises_a_kenyan_phone_number(self, client, owner) -> None:
        response = client.post(
            "/organizations",
            headers=owner["headers"],
            json={"name": "Normalised Ltd", "contact_phone": "+254 733 111 222"},
        )
        assert response.status_code == 201
        assert response.json()["data"]["contact_phone"] == "0733111222"

    def test_accepts_explicit_nulls_for_the_optional_block(self, client, owner) -> None:
        """A client clearing a field sends nulls, which must be accepted as such."""
        response = client.post(
            "/organizations",
            headers=owner["headers"],
            json={
                "name": "Explicit Nulls Ltd",
                "description": None,
                "industry": None,
                "website_url": None,
                "contact_email": None,
                "contact_phone": None,
                "county_code": None,
            },
        )
        assert response.status_code == 201, response.text
        data = response.json()["data"]
        assert data["contact_phone"] is None
        assert data["county_code"] is None


# --------------------------------------------------------------------------- #
# Duplicate slug                                                              #
# --------------------------------------------------------------------------- #
class TestDuplicateSlug:
    def test_a_taken_slug_is_a_conflict(self, client, owner, company) -> None:
        response = client.post(
            "/organizations", headers=owner["headers"], json={"name": "Nakuru Build Co"}
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "CONFLICT"

    def test_a_name_that_derives_a_taken_slug_is_a_conflict(self, client, owner) -> None:
        first = client.post(
            "/organizations", headers=owner["headers"], json={"name": "Unique Name Ltd"}
        )
        assert first.status_code == 201
        slug = first.json()["data"]["slug"]
        second = client.post(
            "/organizations", headers=owner["headers"], json={"name": "UNIQUE NAME LTD"}
        )
        assert second.status_code == 409
        assert slug == "unique-name-ltd"

    def test_a_closed_company_keeps_its_slug(self, client, owner, other_owner, db_session) -> None:
        second = _org_id(client, other_owner["headers"], "Nakuru Build Co Two")
        # Give the company a second owner so it can be closed, then close it.
        _member(client, other_owner["headers"], second, owner["user"], role="OWNER")
        closed = client.delete(f"/organizations/{second}", headers=other_owner["headers"])
        assert closed.status_code == 200

        clash = client.post(
            "/organizations", headers=owner["headers"], json={"name": "Nakuru Build Co Two"}
        )
        assert clash.status_code == 409
        row = db_session.execute(
            select(Organization).where(Organization.slug == "nakuru-build-co-two")
        ).scalar_one()
        assert row.deleted_at is not None

    def test_a_non_latin_name_without_a_slug_is_refused(self, client, owner) -> None:
        response = client.post(
            "/organizations", headers=owner["headers"], json={"name": "建筑有限公司"}
        )
        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Reading and listing                                                         #
# --------------------------------------------------------------------------- #
class TestReadAndList:
    def test_lists_only_companies_the_caller_belongs_to(self, client, owner, other_owner) -> None:
        mine = _org_id(client, owner["headers"], "Mine Ltd")
        _org_id(client, other_owner["headers"], "Theirs Ltd")

        listed = client.get("/organizations", headers=owner["headers"])
        assert listed.status_code == 200
        ids = [row["id"] for row in listed.json()["data"]]
        assert ids == [str(mine)]

    def test_a_non_member_gets_404_not_403(self, client, owner, other_owner) -> None:
        theirs = _org_id(client, other_owner["headers"], "Theirs Ltd")
        response = client.get(f"/organizations/{theirs}", headers=owner["headers"])
        assert response.status_code == 404

    def test_reading_a_missing_company_is_also_404(self, client, owner) -> None:
        assert (
            client.get(f"/organizations/{uuid.uuid4()}", headers=owner["headers"]).status_code
            == 404
        )

    def test_requires_authentication(self, client, company) -> None:
        assert client.get(f"/organizations/{company['id']}").status_code == 401
        assert client.get("/organizations").status_code == 401

    def test_a_suspended_member_loses_access(
        self, client, owner, company, make_user, auth_headers
    ) -> None:
        user = make_user()
        headers = auth_headers(user)
        membership = _member(client, owner["headers"], company["id"], user)
        suspended = client.patch(
            f"/organizations/{company['id']}/members/{membership['id']}",
            headers=owner["headers"],
            json={"status": "SUSPENDED"},
        )
        assert suspended.status_code == 200
        assert client.get(f"/organizations/{company['id']}", headers=headers).status_code == 404
        assert client.get("/organizations", headers=headers).json()["data"] == []

    def test_slug_cannot_be_changed_by_a_member(self, client, owner, company) -> None:
        response = client.patch(
            f"/organizations/{company['id']}",
            headers=owner["headers"],
            json={"slug": "renamed-co"},
        )
        assert response.status_code == 422


class TestUpdate:
    def test_an_owner_updates_the_record(self, client, owner, company) -> None:
        response = client.patch(
            f"/organizations/{company['id']}",
            headers=owner["headers"],
            json={"name": "Nakuru Build Company", "industry": "Civil engineering"},
        )
        assert response.status_code == 200
        assert response.json()["data"]["name"] == "Nakuru Build Company"

    def test_an_empty_patch_is_a_no_op(self, client, owner, company) -> None:
        response = client.patch(
            f"/organizations/{company['id']}", headers=owner["headers"], json={}
        )
        assert response.status_code == 200
        assert response.json()["data"]["name"] == company["name"]

    def test_a_plain_member_may_not_update(self, client, owner, company, make_user, auth_headers):
        user = make_user()
        _member(client, owner["headers"], company["id"], user, role="MEMBER")
        response = client.patch(
            f"/organizations/{company['id']}",
            headers=auth_headers(user),
            json={"name": "Hijacked Ltd"},
        )
        assert response.status_code == 403

    def test_county_is_resolved_through_the_catalogue(self, client, owner, company) -> None:
        response = client.get(f"/organizations/{company['id']}", headers=owner["headers"])
        assert response.json()["data"]["county_code"] == "NAKURU"

    def test_an_unknown_county_code_is_refused(self, client, owner, company) -> None:
        response = client.patch(
            f"/organizations/{company['id']}",
            headers=owner["headers"],
            json={"county_code": "ATLANTIS"},
        )
        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Membership add / list / update / remove                                     #
# --------------------------------------------------------------------------- #
class TestMembershipCrud:
    def test_adds_a_member_by_user_id(self, client, owner, company, make_user) -> None:
        user = make_user()
        response = _add_member(
            client, owner["headers"], company["id"], user_id=str(user.id), role="RECRUITER"
        )
        assert response.status_code == 201, response.text
        data = response.json()["data"]
        assert data["role"] == OrganizationRole.RECRUITER.value
        assert data["status"] == MembershipStatus.ACTIVE.value
        assert data["organization_id"] == company["id"]
        assert data["joined_at"]

    def test_adds_a_member_by_email_case_insensitively(self, client, owner, company, make_user):
        user = make_user()
        response = _add_member(
            client, owner["headers"], company["id"], email=user.email.upper(), title="Foreman"
        )
        assert response.status_code == 201, response.text
        assert response.json()["data"]["title"] == "Foreman"

    def test_an_unknown_email_is_not_found(self, client, owner, company) -> None:
        response = _add_member(
            client, owner["headers"], company["id"], email="nobody@nowhere.example"
        )
        assert response.status_code == 404

    def test_adding_a_member_twice_is_a_conflict(self, client, owner, company, make_user) -> None:
        user = make_user()
        _member(client, owner["headers"], company["id"], user)
        again = _add_member(client, owner["headers"], company["id"], user_id=str(user.id))
        assert again.status_code == 409

    def test_the_response_carries_no_account_identifier(self, client, owner, company, make_user):
        user = make_user()
        data = _member(client, owner["headers"], company["id"], user)
        assert "user_id" not in data
        assert user.email not in str(data)

    @pytest.mark.parametrize(
        "payload",
        [{}, {"user_id": str(uuid.uuid4()), "email": "both@nowhere.example"}],
        ids=["neither", "both"],
    )
    def test_exactly_one_target_is_required(self, client, owner, company, payload) -> None:
        response = _add_member(client, owner["headers"], company["id"], **payload)
        assert response.status_code == 422

    def test_lists_members_with_names_roles_and_statuses(
        self, client, owner, company, make_user, auth_headers, db_session
    ) -> None:
        named = make_user()
        profile = WorkerProfile(user_id=named.id, display_name="Grace Wanjiru")
        db_session.add(profile)
        db_session.flush()
        _member(client, owner["headers"], company["id"], named, role="ADMIN")
        anonymous = make_user()
        _member(client, owner["headers"], company["id"], anonymous)

        response = client.get(f"/organizations/{company['id']}/members", headers=owner["headers"])
        assert response.status_code == 200
        rows = response.json()["data"]
        assert [row["role"] for row in rows] == [
            OrganizationRole.OWNER.value,
            OrganizationRole.ADMIN.value,
            OrganizationRole.MEMBER.value,
        ]
        assert rows[1]["display_name"] == "Grace Wanjiru"
        # No passport, so no name - never the email address instead.
        assert rows[2]["display_name"] is None

    def test_filters_the_roster_by_role_and_status(self, client, owner, company, make_user) -> None:
        _member(client, owner["headers"], company["id"], make_user(), role="RECRUITER")
        response = client.get(
            f"/organizations/{company['id']}/members",
            headers=owner["headers"],
            params={"role": "RECRUITER"},
        )
        assert response.status_code == 200
        assert [row["role"] for row in response.json()["data"]] == [
            OrganizationRole.RECRUITER.value
        ]

    def test_a_plain_member_may_read_the_roster(
        self, client, owner, company, make_user, auth_headers
    ) -> None:
        user = make_user()
        _member(client, owner["headers"], company["id"], user)
        response = client.get(f"/organizations/{company['id']}/members", headers=auth_headers(user))
        assert response.status_code == 200
        assert len(response.json()["data"]) == 2

    def test_owns_its_own_membership(self, client, owner, company, make_user, auth_headers) -> None:
        user = make_user()
        membership = _member(client, owner["headers"], company["id"], user, role="ADMIN")
        response = client.get(f"/organizations/{company['id']}/me", headers=auth_headers(user))
        assert response.status_code == 200
        assert response.json()["data"]["id"] == membership["id"]

    def test_changes_a_role_and_a_title(self, client, owner, company, make_user) -> None:
        user = make_user()
        membership = _member(client, owner["headers"], company["id"], user)
        response = client.patch(
            f"/organizations/{company['id']}/members/{membership['id']}",
            headers=owner["headers"],
            json={"role": "RECRUITER", "title": "Site supervisor"},
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["role"] == OrganizationRole.RECRUITER.value
        assert data["title"] == "Site supervisor"

    def test_an_empty_membership_patch_is_a_no_op(self, client, owner, company, make_user) -> None:
        membership = _member(client, owner["headers"], company["id"], make_user())
        response = client.patch(
            f"/organizations/{company['id']}/members/{membership['id']}",
            headers=owner["headers"],
            json={},
        )
        assert response.status_code == 200
        assert response.json()["data"]["role"] == OrganizationRole.MEMBER.value

    def test_rejects_a_stray_user_id_on_a_membership_patch(
        self, client, owner, company, make_user
    ) -> None:
        membership = _member(client, owner["headers"], company["id"], make_user())
        response = client.patch(
            f"/organizations/{company['id']}/members/{membership['id']}",
            headers=owner["headers"],
            json={"user_id": str(uuid.uuid4()), "role": "OWNER"},
        )
        assert response.status_code == 422

    def test_removes_a_member_and_allows_reinviting(
        self, client, owner, company, make_user
    ) -> None:
        user = make_user()
        membership = _member(client, owner["headers"], company["id"], user)
        removed = client.delete(
            f"/organizations/{company['id']}/members/{membership['id']}",
            headers=owner["headers"],
        )
        assert removed.status_code == 200
        assert removed.json()["data"]["status"] == "DELETED"

        rows = client.get(f"/organizations/{company['id']}/members", headers=owner["headers"])
        assert len(rows.json()["data"]) == 1

        # The unique constraint on (organization_id, user_id) must not block this.
        again = _member(client, owner["headers"], company["id"], user)
        assert again["role"] == OrganizationRole.MEMBER.value

    def test_an_unknown_membership_id_is_404(self, client, owner, company) -> None:
        for method in ("patch", "delete"):
            response = client.request(
                method,
                f"/organizations/{company['id']}/members/{uuid.uuid4()}",
                headers=owner["headers"],
                json={},
            )
            assert response.status_code == 404, response.text

    def test_membership_endpoints_require_authentication(self, client, company) -> None:
        assert client.get(f"/organizations/{company['id']}/members").status_code == 401
        assert (
            client.post(
                f"/organizations/{company['id']}/members", json={"user_id": str(uuid.uuid4())}
            ).status_code
            == 401
        )


# --------------------------------------------------------------------------- #
# Role authorisation                                                          #
# --------------------------------------------------------------------------- #
class TestRoleAuthorisation:
    @pytest.mark.parametrize(
        ("role", "may_add"),
        [
            (OrganizationRole.OWNER, True),
            (OrganizationRole.ADMIN, True),
            (OrganizationRole.RECRUITER, False),
            (OrganizationRole.MEMBER, False),
        ],
    )
    def test_only_owner_and_admin_may_add_members(
        self, client, owner, company, make_user, auth_headers, role, may_add
    ) -> None:
        """A recruiter and a plain member are refused; the response is 403, not 404.

        They already know the company exists - they are in it - so there is nothing
        left to hide, and a 403 tells the client to hide the button rather than
        merely to retry.
        """
        actor = make_user(role=UserRole.EMPLOYER)
        _member(client, owner["headers"], company["id"], actor, role=role.value)
        response = _add_member(
            client, auth_headers(actor), company["id"], user_id=str(make_user().id)
        )
        assert response.status_code == (201 if may_add else 403), response.text

    @pytest.mark.parametrize(
        ("role", "may_manage"),
        [
            (OrganizationRole.OWNER, True),
            (OrganizationRole.ADMIN, True),
            (OrganizationRole.RECRUITER, False),
            (OrganizationRole.MEMBER, False),
        ],
    )
    def test_only_owner_and_admin_may_remove_members(
        self, client, owner, company, make_user, auth_headers, role, may_manage
    ) -> None:
        actor = make_user(role=UserRole.EMPLOYER)
        _member(client, owner["headers"], company["id"], actor, role=role.value)
        target = _member(client, owner["headers"], company["id"], make_user())
        response = client.delete(
            f"/organizations/{company['id']}/members/{target['id']}",
            headers=auth_headers(actor),
        )
        assert response.status_code == (200 if may_manage else 403), response.text

    @pytest.mark.parametrize(
        "role",
        [
            OrganizationRole.OWNER,
            OrganizationRole.ADMIN,
            OrganizationRole.RECRUITER,
            OrganizationRole.MEMBER,
        ],
    )
    def test_every_role_may_read_the_company(
        self, client, owner, company, make_user, auth_headers, role
    ) -> None:
        actor = make_user(role=UserRole.EMPLOYER)
        _member(client, owner["headers"], company["id"], actor, role=role.value)
        assert (
            client.get(f"/organizations/{company['id']}", headers=auth_headers(actor)).status_code
            == 200
        )

    def test_an_admin_may_not_close_the_company(
        self, client, owner, company, make_user, auth_headers
    ) -> None:
        admin = make_user(role=UserRole.EMPLOYER)
        _member(client, owner["headers"], company["id"], admin, role="ADMIN")
        response = client.delete(f"/organizations/{company['id']}", headers=auth_headers(admin))
        assert response.status_code == 403

    def test_an_employer_with_no_membership_can_do_nothing(
        self, client, make_user, auth_headers
    ) -> None:
        """Right platform role, no membership: the company does not exist to them."""
        stranger = make_user(role=UserRole.EMPLOYER)
        headers = auth_headers(stranger)
        unknown = uuid.uuid4()
        for method, url, payload in (
            ("get", f"/organizations/{unknown}", None),
            ("patch", f"/organizations/{unknown}", {"name": "Stolen"}),
            ("delete", f"/organizations/{unknown}", None),
            ("get", f"/organizations/{unknown}/members", None),
            ("get", f"/organizations/{unknown}/me", None),
            ("post", f"/organizations/{unknown}/members", {"user_id": str(uuid.uuid4())}),
        ):
            response = client.request(method, url, headers=headers, json=payload)
            assert response.status_code == 404, (url, response.text)


# --------------------------------------------------------------------------- #
# Cross-organization isolation                                                #
# --------------------------------------------------------------------------- #
class TestCrossOrganization:
    @pytest.mark.parametrize(
        "role",
        [
            OrganizationRole.OWNER,
            OrganizationRole.ADMIN,
            OrganizationRole.RECRUITER,
            OrganizationRole.MEMBER,
        ],
    )
    @pytest.mark.parametrize("method", ["get", "patch", "delete"])
    def test_no_role_reaches_another_company(
        self, client, owner, other_owner, make_user, auth_headers, role, method
    ) -> None:
        """Organization A can never read or mutate Organization B, at any role.

        The actor holds the *most* privileged role in the test when it is an
        OWNER, so a failure here could not be explained by insufficient rights.
        """
        theirs = _org_id(client, other_owner["headers"], "Their Company Ltd")
        actor = make_user(role=UserRole.EMPLOYER)
        _member(
            client,
            owner["headers"],
            _org_id(client, owner["headers"], "Our Company Ltd"),
            actor,
            role=role.value,
        )

        response = client.request(
            method,
            f"/organizations/{theirs}",
            headers=auth_headers(actor),
            json={"name": "Stolen"},
        )
        assert response.status_code == 404, response.text

    def test_members_of_another_company_are_404_not_403(
        self, client, owner, other_owner, make_user, auth_headers
    ) -> None:
        theirs = _org_id(client, other_owner["headers"], "Their Company Ltd")
        stranger = _member(client, other_owner["headers"], theirs, make_user(), role="ADMIN")
        actor = make_user(role=UserRole.EMPLOYER)
        mine = _org_id(client, owner["headers"], "Our Company Ltd")
        _member(client, owner["headers"], mine, actor, role="OWNER")

        response = client.patch(
            f"/organizations/{mine}/members/{stranger['id']}",
            headers=auth_headers(actor),
            json={"role": "OWNER"},
        )
        assert response.status_code == 404, response.text

    def test_a_membership_id_cannot_be_used_in_another_company(
        self, client, owner, other_owner, make_user
    ) -> None:
        theirs = _org_id(client, other_owner["headers"], "Their Company Ltd")
        stranger = _member(client, other_owner["headers"], theirs, make_user())
        response = client.delete(
            f"/organizations/{theirs}/members/{stranger['id']}", headers=other_owner["headers"]
        )
        assert response.status_code == 200
        # Same membership id against a company the caller does own: nothing to find.
        mine = _org_id(client, owner["headers"], "Our Company Ltd")
        absent = client.delete(
            f"/organizations/{mine}/members/{stranger['id']}", headers=owner["headers"]
        )
        assert absent.status_code == 404

    def test_the_roster_of_another_company_is_404(self, client, owner, other_owner) -> None:
        theirs = _org_id(client, other_owner["headers"], "Their Company Ltd")
        assert (
            client.get(f"/organizations/{theirs}/members", headers=owner["headers"]).status_code
            == 404
        )


# --------------------------------------------------------------------------- #
# Last owner protection                                                       #
# --------------------------------------------------------------------------- #
class TestLastOwnerProtection:
    @pytest.fixture
    def sole_owner_membership(self, client, owner, company) -> dict:
        mine = client.get(f"/organizations/{company['id']}/me", headers=owner["headers"])
        return mine.json()["data"]

    def test_the_sole_owner_cannot_demote_themselves(
        self, client, owner, company, sole_owner_membership
    ) -> None:
        response = client.patch(
            f"/organizations/{company['id']}/members/{sole_owner_membership['id']}",
            headers=owner["headers"],
            json={"role": "ADMIN"},
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "LAST_OWNER_PROTECTED"
        assert (
            client.get(f"/organizations/{company['id']}/me", headers=owner["headers"]).json()[
                "data"
            ]["role"]
            == OrganizationRole.OWNER.value
        )

    def test_the_sole_owner_cannot_suspend_themselves(
        self, client, owner, company, sole_owner_membership
    ) -> None:
        response = client.patch(
            f"/organizations/{company['id']}/members/{sole_owner_membership['id']}",
            headers=owner["headers"],
            json={"status": "SUSPENDED"},
        )
        assert response.status_code == 409

    def test_the_sole_owner_cannot_remove_themselves(
        self, client, owner, company, sole_owner_membership
    ) -> None:
        response = client.delete(
            f"/organizations/{company['id']}/members/{sole_owner_membership['id']}",
            headers=owner["headers"],
        )
        assert response.status_code == 409

    def test_the_sole_owner_cannot_delete_the_company(self, client, owner, company) -> None:
        response = client.delete(f"/organizations/{company['id']}", headers=owner["headers"])
        assert response.status_code == 409
        assert (
            client.get(f"/organizations/{company['id']}", headers=owner["headers"]).status_code
            == 200
        )

    def test_a_non_owner_cannot_delete_the_last_owner(
        self, client, owner, company, make_user, auth_headers
    ) -> None:
        admin = make_user(role=UserRole.EMPLOYER)
        _member(client, owner["headers"], company["id"], admin, role="ADMIN")
        mine = client.get(f"/organizations/{company['id']}/me", headers=owner["headers"])
        response = client.delete(
            f"/organizations/{company['id']}/members/{mine.json()['data']['id']}",
            headers=auth_headers(admin),
        )
        assert response.status_code == 403

    def test_the_guard_lifts_once_a_second_owner_exists(
        self, client, owner, company, other_owner
    ) -> None:
        co_owner = _member(
            client, owner["headers"], company["id"], other_owner["user"], role="OWNER"
        )
        assert co_owner["role"] == OrganizationRole.OWNER.value

        mine = client.get(f"/organizations/{company['id']}/me", headers=owner["headers"])
        demoted = client.patch(
            f"/organizations/{company['id']}/members/{mine.json()['data']['id']}",
            headers=owner["headers"],
            json={"role": "ADMIN"},
        )
        assert demoted.status_code == 200

        # An owner may also remove themselves while a second owner remains.
        left = client.delete(
            f"/organizations/{company['id']}/members/{mine.json()['data']['id']}",
            headers=owner["headers"],
        )
        assert left.status_code == 200
        assert (
            client.get(f"/organizations/{company['id']}/me", headers=owner["headers"]).status_code
            == 404
        )

        # ...but the company is now down to one owner, so it cannot be closed either.
        assert (
            client.delete(
                f"/organizations/{company['id']}", headers=other_owner["headers"]
            ).status_code
            == 409
        )
        _member(client, other_owner["headers"], company["id"], owner["user"], role="OWNER")
        closed = client.delete(f"/organizations/{company['id']}", headers=other_owner["headers"])
        assert closed.status_code == 200

    def test_demoting_the_last_owner_is_refused_for_any_caller(
        self, client, owner, company, make_user, auth_headers
    ) -> None:
        """Only an owner may touch an owner's membership - and never the last one."""
        admin = make_user(role=UserRole.EMPLOYER)
        _member(client, owner["headers"], company["id"], admin, role="ADMIN")
        mine = client.get(f"/organizations/{company['id']}/me", headers=owner["headers"])

        # An admin may not suspend or demote the owner's membership at all.
        for payload in ({"status": "SUSPENDED"}, {"role": "MEMBER"}):
            response = client.patch(
                f"/organizations/{company['id']}/members/{mine.json()['data']['id']}",
                headers=auth_headers(admin),
                json=payload,
            )
            assert response.status_code == 403, response.text

        # The owner still is, and can therefore still act.
        assert (
            client.get(f"/organizations/{company['id']}/me", headers=owner["headers"]).json()[
                "data"
            ]["role"]
            == OrganizationRole.OWNER.value
        )


# --------------------------------------------------------------------------- #
# Self escalation                                                             #
# --------------------------------------------------------------------------- #
class TestSelfEscalation:
    @pytest.fixture
    def admin_member(self, client, owner, company, make_user, auth_headers) -> dict:
        admin = make_user(role=UserRole.EMPLOYER)
        membership = _member(client, owner["headers"], company["id"], admin, role="ADMIN")
        return {"user": admin, "membership": membership, "headers": auth_headers(admin)}

    def test_an_admin_cannot_grant_ownership(
        self, client, owner, company, admin_member, make_user
    ) -> None:
        response = _add_member(
            client,
            admin_member["headers"],
            company["id"],
            user_id=str(make_user().id),
            role="OWNER",
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "ORG_OWNERSHIP_GRANT_RESERVED"

    def test_an_admin_cannot_promote_themselves_to_owner(
        self, client, owner, company, admin_member
    ) -> None:
        response = client.patch(
            f"/organizations/{company['id']}/members/{admin_member['membership']['id']}",
            headers=admin_member["headers"],
            json={"role": "OWNER"},
        )
        assert response.status_code == 403

    def test_nobody_can_add_themselves(self, client, owner, company, admin_member) -> None:
        response = _add_member(
            client, admin_member["headers"], company["id"], user_id=str(admin_member["user"].id)
        )
        assert response.status_code == 403

    def test_nobody_can_add_themselves_as_owner_by_email(
        self, client, owner, company, admin_member
    ) -> None:
        response = _add_member(
            client,
            admin_member["headers"],
            company["id"],
            email=admin_member["user"].email,
            role="OWNER",
        )
        assert response.status_code == 403

    def test_an_admin_cannot_remove_an_owner(self, client, owner, company, admin_member) -> None:
        mine = client.get(f"/organizations/{company['id']}/me", headers=owner["headers"])
        response = client.patch(
            f"/organizations/{company['id']}/members/{mine.json()['data']['id']}",
            headers=admin_member["headers"],
            json={"role": "MEMBER"},
        )
        assert response.status_code == 403

    def test_a_stray_role_in_an_organization_patch_is_422(self, client, owner, company) -> None:
        response = client.patch(
            f"/organizations/{company['id']}", headers=owner["headers"], json={"role": "ADMIN"}
        )
        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Privacy                                                                     #
# --------------------------------------------------------------------------- #
class TestPrivacy:
    def test_the_roster_never_contains_a_member_email(
        self, client, owner, company, make_user, db_session
    ) -> None:
        user = make_user()
        db_session.add(WorkerProfile(user_id=user.id, display_name="Peter Kimani"))
        db_session.flush()
        _member(client, owner["headers"], company["id"], user)

        response = client.get(f"/organizations/{company['id']}/members", headers=owner["headers"])
        assert response.status_code == 200
        assert user.email not in response.text
        assert "@example.com" not in response.text
        assert response.json()["data"][1]["display_name"] == "Peter Kimani"

    def test_the_membership_schema_cannot_carry_contact_details(self) -> None:
        """The guarantee is structural, not a service convention."""
        assert set(MembershipResponse.model_fields) == {
            "id",
            "organization_id",
            "role",
            "status",
            "title",
            "display_name",
            "joined_at",
            "created_at",
            "updated_at",
        }

    def test_a_plain_member_sees_no_company_contact_block(
        self, client, owner, company, make_user, auth_headers
    ) -> None:
        worker = make_user(role=UserRole.WORKER)
        _member(client, owner["headers"], company["id"], worker)
        response = client.get(f"/organizations/{company['id']}", headers=auth_headers(worker))
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["contact_email"] is None
        assert data["contact_phone"] is None
        assert "0712345678" not in response.text
        # ...while the published company information is still there.
        assert data["name"] == "Nakuru Build Co"
        assert data["website_url"] == "https://nakuru-build.example"

    def test_a_recruiter_sees_no_company_contact_block(
        self, client, owner, company, make_user, auth_headers
    ) -> None:
        recruiter = make_user(role=UserRole.EMPLOYER)
        _member(client, owner["headers"], company["id"], recruiter, role="RECRUITER")
        response = client.get(f"/organizations/{company['id']}", headers=auth_headers(recruiter))
        assert response.json()["data"]["contact_email"] is None

    def test_an_admin_sees_the_company_contact_block(
        self, client, owner, company, make_user, auth_headers
    ) -> None:
        admin = make_user(role=UserRole.EMPLOYER)
        _member(client, owner["headers"], company["id"], admin, role="ADMIN")
        data = client.get(f"/organizations/{company['id']}", headers=auth_headers(admin)).json()[
            "data"
        ]
        assert data["contact_email"] == "hello@nakuru-build.example"
        assert data["contact_phone"] == "0712345678"

    def test_the_list_never_includes_the_contact_block(self, client, owner, company) -> None:
        response = client.get("/organizations", headers=owner["headers"])
        assert "contact_email" not in response.json()["data"][0]
        assert "contact_email" not in response.text

    def test_a_soft_deleted_profile_yields_no_name(
        self, client, owner, company, make_user, db_session
    ) -> None:
        from app.db.base import utcnow

        user = make_user()
        profile = WorkerProfile(user_id=user.id, display_name="Withdrawn", deleted_at=utcnow())
        db_session.add(profile)
        db_session.flush()
        _member(client, owner["headers"], company["id"], user)
        rows = client.get(
            f"/organizations/{company['id']}/members", headers=owner["headers"]
        ).json()["data"]
        assert rows[1]["display_name"] is None


# --------------------------------------------------------------------------- #
# Pagination                                                                  #
# --------------------------------------------------------------------------- #
class TestPagination:
    @pytest.fixture
    def crowded(self, client, owner, company, make_user) -> dict:
        for index in range(5):
            _member(client, owner["headers"], company["id"], make_user(), title=f"Worker {index}")
        return company

    def test_the_roster_paginates(self, client, owner, crowded) -> None:
        first = client.get(
            f"/organizations/{crowded['id']}/members",
            headers=owner["headers"],
            params={"page": 1, "page_size": 2},
        )
        assert first.status_code == 200
        body = first.json()
        assert len(body["data"]) == 2
        assert body["meta"] == {
            "request_id": body["meta"]["request_id"],
            "page": 1,
            "page_size": 2,
            "total_items": 6,
            "total_pages": 3,
            "has_next": True,
            "has_previous": False,
        }

        second = client.get(
            f"/organizations/{crowded['id']}/members",
            headers=owner["headers"],
            params={"page": 2, "page_size": 2},
        ).json()
        assert {row["id"] for row in second["data"]}.isdisjoint({row["id"] for row in body["data"]})

        last = client.get(
            f"/organizations/{crowded['id']}/members",
            headers=owner["headers"],
            params={"page": 3, "page_size": 2},
        ).json()
        assert len(last["data"]) == 2
        assert last["meta"]["has_previous"] is True

    def test_a_page_past_the_end_is_empty_not_an_error(self, client, owner, crowded) -> None:
        response = client.get(
            f"/organizations/{crowded['id']}/members",
            headers=owner["headers"],
            params={"page": 99, "page_size": 10},
        )
        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["total_items"] == 6

    def test_the_company_list_paginates(self, client, owner) -> None:
        for index in range(3):
            _org_id(client, owner["headers"], f"Paginated Company {index}")
        response = client.get(
            "/organizations", headers=owner["headers"], params={"page": 1, "page_size": 2}
        )
        body = response.json()
        assert len(body["data"]) == 2
        assert body["meta"]["total_items"] == 3
        assert body["meta"]["has_next"] is True

    def test_page_size_is_capped(self, client, owner) -> None:
        response = client.get("/organizations", headers=owner["headers"], params={"page_size": 500})
        assert response.status_code == 422

    def test_page_zero_is_refused(self, client, owner) -> None:
        response = client.get("/organizations", headers=owner["headers"], params={"page": 0})
        assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Closing a company, and the administrator surface                             #
# --------------------------------------------------------------------------- #
class TestClosing:
    def test_closing_is_a_soft_delete(self, client, owner, other_owner, db_session) -> None:
        organization_id = _org_id(client, owner["headers"], "Closing Time Ltd")
        _member(client, owner["headers"], organization_id, other_owner["user"], role="OWNER")
        closed = client.delete(f"/organizations/{organization_id}", headers=owner["headers"])
        assert closed.status_code == 200
        assert closed.json()["data"]["status"] == "DELETED"

        row = db_session.execute(
            select(Organization).where(Organization.id == organization_id)
        ).scalar_one()
        assert row.deleted_at is not None
        assert row.is_active is False
        # The row survives: jobs, applications and audit rows still resolve it.
        assert (
            client.get(f"/organizations/{organization_id}", headers=owner["headers"]).status_code
            == 404
        )


class TestAdministratorSurface:
    def test_an_administrator_lists_reads_and_verifies(
        self, client, owner, company, make_admin, auth_headers
    ) -> None:
        admin = make_admin()
        headers = auth_headers(admin)
        listed = client.get("/admin/organizations", headers=headers)
        assert listed.status_code == 200
        assert any(row["id"] == company["id"] for row in listed.json()["data"])

        verified = client.patch(
            f"/admin/organizations/{company['id']}", headers=headers, json={"is_verified": True}
        )
        assert verified.status_code == 200
        assert verified.json()["data"]["is_verified"] is True
        assert (
            client.get(f"/organizations/{company['id']}", headers=owner["headers"]).json()["data"][
                "is_verified"
            ]
            is True
        )

    def test_an_administrator_closes_a_sole_owner_company(
        self, client, owner, company, make_admin, auth_headers
    ) -> None:
        admin = make_admin()
        response = client.delete(
            f"/admin/organizations/{company['id']}", headers=auth_headers(admin)
        )
        assert response.status_code == 200

    def test_the_administrator_surface_is_closed_to_other_roles(
        self, client, owner, company
    ) -> None:
        for method, url, payload in (
            ("get", "/admin/organizations", None),
            ("get", f"/admin/organizations/{company['id']}", None),
            ("patch", f"/admin/organizations/{company['id']}", {"is_verified": True}),
            ("delete", f"/admin/organizations/{company['id']}", None),
        ):
            response = client.request(method, url, headers=owner["headers"], json=payload)
            assert response.status_code == 403, (url, response.text)

    def test_an_administrator_reads_one_company(self, client, company, make_admin, auth_headers):
        headers = auth_headers(make_admin())
        response = client.get(f"/admin/organizations/{company['id']}", headers=headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["contact_email"] == "hello@nakuru-build.example"
        assert data["deleted_at"] is None

    def test_an_administrator_reads_a_closed_company(
        self, client, company, make_admin, auth_headers
    ) -> None:
        headers = auth_headers(make_admin())
        closed = client.delete(f"/admin/organizations/{company['id']}", headers=headers)
        assert closed.status_code == 200
        read = client.get(f"/admin/organizations/{company['id']}", headers=headers)
        assert read.status_code == 200
        assert read.json()["data"]["deleted_at"] is not None

    def test_an_administrator_filters_the_listing(
        self, client, company, make_admin, auth_headers
    ) -> None:
        headers = auth_headers(make_admin())
        verified = client.patch(
            f"/admin/organizations/{company['id']}", headers=headers, json={"is_verified": True}
        )
        assert verified.status_code == 200
        filtered = client.get("/admin/organizations", headers=headers, params={"is_verified": True})
        assert [row["id"] for row in filtered.json()["data"]] == [company["id"]]

    def test_an_empty_administrator_patch_is_a_no_op(
        self, client, company, make_admin, auth_headers
    ) -> None:
        response = client.patch(
            f"/admin/organizations/{company['id']}",
            headers=auth_headers(make_admin()),
            json={},
        )
        assert response.status_code == 200
        assert response.json()["data"]["is_verified"] is False


# --------------------------------------------------------------------------- #
# Audit                                                                       #
# --------------------------------------------------------------------------- #
class TestAuditTrail:
    def test_creation_and_membership_changes_are_recorded(
        self, client, owner, company, make_user, audit_rows
    ) -> None:
        from app.core.constants import AuditAction

        user = make_user()
        membership = _member(client, owner["headers"], company["id"], user, role="ADMIN")
        client.patch(
            f"/organizations/{company['id']}/members/{membership['id']}",
            headers=owner["headers"],
            json={"role": "RECRUITER"},
        )
        client.delete(
            f"/organizations/{company['id']}/members/{membership['id']}",
            headers=owner["headers"],
        )

        assert audit_rows(
            action=AuditAction.ADMIN_ACTION.value, resource_id=uuid.UUID(company["id"])
        )
        added = audit_rows(action=AuditAction.MEMBERSHIP_ADDED.value)
        assert [row.metadata_["granted_role"] for row in added] == ["ADMIN"]
        changed = audit_rows(action=AuditAction.MEMBERSHIP_ROLE_CHANGED.value)
        assert changed[-1].metadata_["new_role"] == OrganizationRole.RECRUITER.value
        removed = audit_rows(action=AuditAction.MEMBERSHIP_REMOVED.value)
        assert removed[-1].metadata_["subject_user_id"] == str(user.id)

    def test_a_refusal_survives_the_rollback_of_the_effect(
        self, client, owner, company, make_user, audit_rows
    ) -> None:
        """A trail that records only the grants would be worse than no trail."""
        from app.core.constants import AuditAction

        mine = client.get(f"/organizations/{company['id']}/me", headers=owner["headers"])
        denied = client.patch(
            f"/organizations/{company['id']}/members/{mine.json()['data']['id']}",
            headers=owner["headers"],
            json={"role": "MEMBER"},
        )
        assert denied.status_code == 409

        refusals = audit_rows(action=AuditAction.MEMBERSHIP_ROLE_CHANGED.value, outcome="DENIED")
        assert refusals
        assert refusals[-1].metadata_["reason"] == "LAST_OWNER_PROTECTED"

    def test_no_member_email_reaches_the_audit_trail(
        self, client, owner, company, make_user, audit_rows
    ) -> None:
        user = make_user()
        _member(client, owner["headers"], company["id"], user)
        assert all(user.email not in str(row.metadata_) for row in audit_rows())


# --------------------------------------------------------------------------- #
# Unprefixed paths                                                            #
# --------------------------------------------------------------------------- #
class TestUnprefixedPaths:
    def test_no_api_v1_surface_exists(self, client, owner, company) -> None:
        assert client.get("/organizations", headers=owner["headers"]).status_code == 200
        for path in (
            "/api/v1/organizations",
            "/api/organizations",
            "/v1/organizations",
            f"/api/v1/organizations/{company['id']}",
        ):
            assert client.get(path, headers=owner["headers"]).status_code == 404, path

    def test_the_openapi_document_lists_the_unprefixed_paths(self, client) -> None:
        paths = client.get("/openapi.json").json()["paths"]
        assert "/organizations" in paths
        assert "/organizations/{organization_id}" in paths
        assert "/organizations/{organization_id}/members" in paths
        assert "/admin/organizations" in paths
        assert not [path for path in paths if path.startswith("/api")]

    def test_a_membership_row_is_created_for_the_creator(self, db_session, owner, company) -> None:
        row = db_session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == uuid.UUID(company["id"])
            )
        ).scalar_one()
        assert row.user_id == owner["user"].id
        assert row.role == OrganizationRole.OWNER.value
