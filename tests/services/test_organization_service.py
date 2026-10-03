"""Service-level tests for the branches the HTTP suite cannot reach.

The API tests cover the routes and the authorisation boundary. What they cannot
reach is a branch no route ever takes: an organization row that exists only
outside the API, an administrator calling a service method directly, a caller
whose membership belongs to a different company, and the failure messages that
only a unit of work sees. Those are the branches where a silent wrong answer
would be worst, so they are tested here against a real session.
"""

from __future__ import annotations

import uuid

from pydantic import ValidationError as PydanticValidationError
import pytest
from sqlalchemy import select

from app.core.constants import AuditAction, MembershipStatus, OrganizationRole, UserRole
from app.core.exceptions import (
    ForbiddenError,
    InsufficientRoleError,
    NotFoundError,
    ValidationError,
)
from app.db.base import utcnow
from app.db.models.catalogue import County
from app.db.models.organization import Organization, OrganizationMembership
from app.db.models.worker import WorkerProfile
from app.schemas.organizations import (
    MembershipCreateRequest,
    MembershipUpdateRequest,
    OrganizationAdminUpdateRequest,
    OrganizationCreateRequest,
    OrganizationUpdateRequest,
    normalise_kenyan_phone,
)
from app.services.organization_service import (
    DuplicateSlugError,
    LastOwnerError,
    MembershipExistsError,
    MembershipNotFoundError,
    OrganizationNotFoundError,
    OrganizationRoleEscalationError,
    OrganizationService,
    SelfMembershipError,
    derive_slug,
)

pytestmark = pytest.mark.integration


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture
def employer(db_session, make_user):
    return make_user(role=UserRole.EMPLOYER)


@pytest.fixture
def worker(db_session, make_user):
    return make_user()


@pytest.fixture
def county(db_session) -> County:
    row = County(code="NAKURU", name="Nakuru")
    db_session.add(row)
    db_session.flush()
    return row


@pytest.fixture
def service(db_session) -> OrganizationService:
    return OrganizationService(db_session)


def _make_organization(
    db_session,
    owner,
    *,
    name: str = "Service Test Ltd",
    slug: str | None = None,
    role: OrganizationRole = OrganizationRole.OWNER,
    status: MembershipStatus = MembershipStatus.ACTIVE,
) -> Organization:
    """Insert a company with one membership, bypassing the service on purpose."""
    organization = Organization(
        name=name,
        slug=slug or derive_slug(name),
        is_active=True,
        is_verified=False,
    )
    db_session.add(organization)
    db_session.flush()
    db_session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=owner.id,
            role=role.value,
            status=status.value,
            joined_at=utcnow() if status is MembershipStatus.ACTIVE else None,
        )
    )
    db_session.flush()
    return organization


def _add_membership(
    db_session, organization: Organization, user, role: OrganizationRole
) -> OrganizationMembership:
    membership = OrganizationMembership(
        organization_id=organization.id,
        user_id=user.id,
        role=role.value,
        status=MembershipStatus.ACTIVE.value,
        joined_at=utcnow(),
    )
    db_session.add(membership)
    db_session.flush()
    return membership


# --------------------------------------------------------------------------- #
# Slug derivation                                                             #
# --------------------------------------------------------------------------- #
class TestSlugDerivation:
    @pytest.mark.parametrize(
        ("name", "slug"),
        [
            ("Nakuru Build Co", "nakuru-build-co"),
            ("  Mombasa   Marine Works  ", "mombasa-marine-works"),
            ("Café & Co (Kenya) Ltd", "cafe-co-kenya-ltd"),
            ("Nakuru/Bomet/Turkana", "nakuru-bomet-turkana"),
            ("A1  B2  C3", "a1-b2-c3"),
        ],
    )
    def test_derives_a_url_safe_slug(self, name: str, slug: str) -> None:
        assert derive_slug(name) == slug

    def test_a_long_name_is_truncated_to_the_column_width(self) -> None:
        slug = derive_slug("B" * 200)
        assert len(slug) == 120

    @pytest.mark.parametrize("name", ["建筑有限公司", "???"])
    def test_a_name_with_nothing_usable_is_refused(self, name: str) -> None:
        """Better to be asked for a slug than to be given a meaningless one."""
        with pytest.raises(ValidationError):
            derive_slug(name)

    def test_a_taken_slug_is_a_conflict(self, db_session, service, employer) -> None:
        service.create(actor=employer, payload=OrganizationCreateRequest(name="Taken Slug Ltd"))
        with pytest.raises(DuplicateSlugError):
            service.create(
                actor=employer,
                payload=OrganizationCreateRequest(name="Other Name Ltd", slug="taken-slug-ltd"),
            )

    def test_a_slug_written_outside_the_api_still_blocks_a_duplicate(
        self, db_session, service, employer
    ) -> None:
        """Defence in depth: seeds and migrations may not respect the pattern."""
        _make_organization(db_session, employer, name="Legacy Ltd", slug="LEGACY-LTD")
        with pytest.raises(DuplicateSlugError):
            service.create(
                actor=employer,
                payload=OrganizationCreateRequest(name="Legacy Copy", slug="legacy-ltd"),
            )

    def test_the_request_schema_rejects_an_upper_case_slug(self) -> None:
        with pytest.raises(PydanticValidationError):
            OrganizationCreateRequest(name="Shouting Ltd", slug="SHOUTING-LTD")


# --------------------------------------------------------------------------- #
# Creation                                                                    #
# --------------------------------------------------------------------------- #
class TestCreation:
    def test_a_worker_account_is_refused(self, service, worker) -> None:
        with pytest.raises(InsufficientRoleError):
            service.create(actor=worker, payload=OrganizationCreateRequest(name="Worker Ltd"))

    def test_an_administrator_may_create(self, service, db_session, make_admin) -> None:
        admin = make_admin()
        view = service.create(actor=admin, payload=OrganizationCreateRequest(name="Admin Made Ltd"))
        assert view.organization.is_verified is False
        membership = db_session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == view.organization.id
            )
        ).scalar_one()
        assert membership.user_id == admin.id
        assert membership.role == OrganizationRole.OWNER.value

    def test_the_catalogue_county_is_resolved_and_named(self, service, employer, county) -> None:
        view = service.create(
            actor=employer,
            payload=OrganizationCreateRequest(name="County Ltd", county_code="NAKURU"),
        )
        assert view.county is not None
        assert view.organization.county_id == county.id
        assert view.organization.county == "Nakuru"

    def test_an_unknown_county_is_refused(self, service, employer) -> None:
        with pytest.raises(ValidationError):
            service.create(
                actor=employer,
                payload=OrganizationCreateRequest(name="Bad County Ltd", county_code="ATLANTIS"),
            )

    def test_a_company_without_a_county_is_allowed(self, service, employer) -> None:
        view = service.create(
            actor=employer, payload=OrganizationCreateRequest(name="No County Ltd")
        )
        assert view.county is None
        assert view.organization.county_id is None


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
class TestReads:
    def test_a_non_member_cannot_read(self, service, db_session, employer, worker) -> None:
        organization = _make_organization(db_session, employer)
        with pytest.raises(OrganizationNotFoundError):
            service.get_membership(actor=worker, organization_id=organization.id)

    def test_a_pending_membership_cannot_read(self, service, db_session, employer, worker) -> None:
        organization = _make_organization(db_session, employer)
        _add_membership(db_session, organization, worker, OrganizationRole.MEMBER)
        membership = db_session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id,
                OrganizationMembership.user_id == worker.id,
            )
        ).scalar_one()
        membership.status = MembershipStatus.INVITED.value
        db_session.flush()

        with pytest.raises(OrganizationNotFoundError):
            service.get_membership(actor=worker, organization_id=organization.id)

    def test_a_closed_company_cannot_be_read_by_its_members(
        self, service, db_session, employer
    ) -> None:
        organization = _make_organization(db_session, employer)
        organization.deleted_at = utcnow()
        db_session.flush()
        with pytest.raises(OrganizationNotFoundError):
            service.get_membership(actor=employer, organization_id=organization.id)

    def test_the_listing_covers_only_active_memberships(
        self, service, db_session, employer, worker
    ) -> None:
        live = _make_organization(db_session, employer, name="Live Ltd")
        closed = _make_organization(db_session, employer, name="Closed Ltd")
        closed.deleted_at = utcnow()
        shared = _make_organization(db_session, employer, name="Shared Ltd")
        membership = _add_membership(db_session, shared, worker, OrganizationRole.MEMBER)
        membership.status = MembershipStatus.SUSPENDED.value
        db_session.flush()

        views, total = service.list_for_actor(actor=employer)
        # A closed company is hidden from its own owner too: the slug, the row and
        # the history stay, the company does not reappear.
        assert total == 2
        assert {view.organization.id for view in views} == {live.id, shared.id}

        views, total = service.list_for_actor(actor=worker, limit=0)
        assert total == 0
        assert views == []

    def test_an_empty_roster_page_resolves_no_names(
        self, service, db_session, employer, worker
    ) -> None:
        """The name lookup short-circuits rather than issuing `IN ()`."""
        organization = _make_organization(db_session, employer)
        _add_membership(db_session, organization, worker, OrganizationRole.MEMBER)
        views, total = service.list_members(
            actor=employer, organization_id=organization.id, limit=0
        )
        assert total == 2
        assert views == []

    def test_roster_filters_and_display_names(self, service, db_session, employer, worker) -> None:
        organization = _make_organization(db_session, employer)
        db_session.add(WorkerProfile(user_id=worker.id, display_name="Named Worker"))
        db_session.flush()
        _add_membership(db_session, organization, worker, OrganizationRole.RECRUITER)

        views, total = service.list_members(actor=employer, organization_id=organization.id)
        assert total == 2
        assert views[0].membership.role == OrganizationRole.OWNER.value
        assert views[1].display_name == "Named Worker"

        recruiters, total = service.list_members(
            actor=employer, organization_id=organization.id, role=OrganizationRole.RECRUITER
        )
        assert total == 1
        assert recruiters[0].membership.user_id == worker.id

        suspended, total = service.list_members(
            actor=employer,
            organization_id=organization.id,
            status=MembershipStatus.SUSPENDED,
        )
        assert (total, suspended) == (0, [])


# --------------------------------------------------------------------------- #
# Updating the company                                                        #
# --------------------------------------------------------------------------- #
class TestUpdate:
    def test_a_recruiter_cannot_edit(self, service, db_session, employer, worker) -> None:
        organization = _make_organization(db_session, employer)
        _add_membership(db_session, organization, worker, OrganizationRole.RECRUITER)
        with pytest.raises(ForbiddenError):
            # Refused by role, not by absence: they are a member, so 403 is the
            # honest answer and 404 would tell them nothing they do not know.
            service.update(
                actor=worker,
                organization_id=organization.id,
                payload=OrganizationUpdateRequest(name="Hijacked Ltd"),
            )

    def test_an_admin_may_edit_and_clear_the_county(
        self, service, db_session, employer, worker, county
    ) -> None:
        organization = _make_organization(db_session, employer)
        organization.county_id = county.id
        organization.county = county.name
        db_session.flush()
        _add_membership(db_session, organization, worker, OrganizationRole.ADMIN)

        view = service.update(
            actor=worker,
            organization_id=organization.id,
            payload=OrganizationUpdateRequest(county_code=None, location="Eldoret"),
        )
        assert view.organization.county_id is None
        assert view.organization.county is None
        assert view.organization.location == "Eldoret"

    def test_an_empty_patch_changes_nothing(self, service, db_session, employer) -> None:
        organization = _make_organization(db_session, employer)
        view = service.update(
            actor=employer,
            organization_id=organization.id,
            payload=OrganizationUpdateRequest(),
        )
        assert view.organization.name == organization.name


# --------------------------------------------------------------------------- #
# Memberships                                                                 #
# --------------------------------------------------------------------------- #
class TestMembershipWrites:
    def test_an_unknown_user_id_is_not_found(self, service, db_session, employer) -> None:
        organization = _make_organization(db_session, employer)
        with pytest.raises(NotFoundError):
            service.add_member(
                actor=employer,
                organization_id=organization.id,
                payload=MembershipCreateRequest(user_id=uuid.uuid4()),
            )

    def test_a_soft_deleted_account_cannot_be_added(
        self, service, db_session, employer, worker
    ) -> None:
        organization = _make_organization(db_session, employer)
        worker.deleted_at = utcnow()
        db_session.flush()
        with pytest.raises(NotFoundError):
            service.add_member(
                actor=employer,
                organization_id=organization.id,
                payload=MembershipCreateRequest(email=worker.email),
            )

    def test_a_pending_invitation_has_no_joined_at(
        self, service, db_session, employer, worker
    ) -> None:
        organization = _make_organization(db_session, employer)
        view = service.add_member(
            actor=employer,
            organization_id=organization.id,
            payload=MembershipCreateRequest(user_id=worker.id, status=MembershipStatus.INVITED),
        )
        assert view.membership.status == MembershipStatus.INVITED.value
        assert view.membership.joined_at is None

    def test_adding_twice_is_a_conflict(self, service, db_session, employer, worker) -> None:
        organization = _make_organization(db_session, employer)
        payload = MembershipCreateRequest(user_id=worker.id)
        service.add_member(actor=employer, organization_id=organization.id, payload=payload)
        with pytest.raises(MembershipExistsError):
            service.add_member(actor=employer, organization_id=organization.id, payload=payload)

    def test_an_admin_may_not_grant_ownership(self, service, db_session, employer, worker) -> None:
        organization = _make_organization(db_session, employer)
        admin_membership = _add_membership(db_session, organization, worker, OrganizationRole.ADMIN)
        with pytest.raises(OrganizationRoleEscalationError):
            service.update_member(
                actor=worker,
                organization_id=organization.id,
                membership_id=admin_membership.id,
                payload=MembershipUpdateRequest(role=OrganizationRole.OWNER),
            )

    def test_self_addition_is_refused(self, service, db_session, employer) -> None:
        organization = _make_organization(db_session, employer)
        with pytest.raises(SelfMembershipError):
            service.add_member(
                actor=employer,
                organization_id=organization.id,
                payload=MembershipCreateRequest(user_id=employer.id),
            )

    def test_a_membership_from_another_company_is_not_found(
        self, service, db_session, employer, worker
    ) -> None:
        """The parent is in the WHERE clause, so the lookup simply misses."""
        mine = _make_organization(db_session, employer, name="Mine Ltd")
        theirs = _make_organization(db_session, employer, name="Theirs Ltd")
        stranger = _add_membership(db_session, theirs, worker, OrganizationRole.MEMBER)

        with pytest.raises(MembershipNotFoundError):
            service.update_member(
                actor=employer,
                organization_id=mine.id,
                membership_id=stranger.id,
                payload=MembershipUpdateRequest(title="Not mine"),
            )
        with pytest.raises(MembershipNotFoundError):
            service.remove_member(
                actor=employer, organization_id=mine.id, membership_id=stranger.id
            )

    def test_an_owner_may_demote_while_another_owner_remains(
        self, service, db_session, employer, worker
    ) -> None:
        organization = _make_organization(db_session, employer)
        _add_membership(db_session, organization, worker, OrganizationRole.OWNER)
        owner_membership = db_session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id,
                OrganizationMembership.user_id == employer.id,
            )
        ).scalar_one()

        view = service.update_member(
            actor=employer,
            organization_id=organization.id,
            membership_id=owner_membership.id,
            payload=MembershipUpdateRequest(role=OrganizationRole.ADMIN),
        )
        assert view.membership.role == OrganizationRole.ADMIN.value

    def test_a_title_only_change_is_not_treated_as_a_role_change(
        self, service, db_session, employer, worker
    ) -> None:
        """Editing a job title changes no authority, so it skips the role checks."""
        organization = _make_organization(db_session, employer)
        membership = _add_membership(db_session, organization, worker, OrganizationRole.MEMBER)
        view = service.update_member(
            actor=employer,
            organization_id=organization.id,
            membership_id=membership.id,
            payload=MembershipUpdateRequest(title="Site agent"),
        )
        assert view.membership.title == "Site agent"
        assert view.membership.role == OrganizationRole.MEMBER.value

    def test_a_title_may_also_be_cleared(self, service, db_session, employer, worker) -> None:
        organization = _make_organization(db_session, employer)
        membership = _add_membership(db_session, organization, worker, OrganizationRole.MEMBER)
        membership.title = "Site agent"
        db_session.flush()
        view = service.update_member(
            actor=employer,
            organization_id=organization.id,
            membership_id=membership.id,
            payload=MembershipUpdateRequest(title=None),
        )
        assert view.membership.title is None

    def test_re_affirming_ownership_is_allowed(self, service, db_session, employer) -> None:
        """The guard is about losing the last owner, not about touching ownership."""
        organization = _make_organization(db_session, employer)
        owner_membership = db_session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id
            )
        ).scalar_one()
        view = service.update_member(
            actor=employer,
            organization_id=organization.id,
            membership_id=owner_membership.id,
            payload=MembershipUpdateRequest(role=OrganizationRole.OWNER, title="Managing director"),
        )
        assert view.membership.role == OrganizationRole.OWNER.value
        assert view.membership.title == "Managing director"

    def test_suspending_the_only_owner_is_refused(self, service, db_session, employer) -> None:
        organization = _make_organization(db_session, employer)
        owner_membership = db_session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id
            )
        ).scalar_one()
        with pytest.raises(LastOwnerError):
            service.update_member(
                actor=employer,
                organization_id=organization.id,
                membership_id=owner_membership.id,
                payload=MembershipUpdateRequest(status=MembershipStatus.SUSPENDED),
            )

    def test_reactivating_sets_joined_at(self, service, db_session, employer, worker) -> None:
        organization = _make_organization(db_session, employer)
        membership = _add_membership(db_session, organization, worker, OrganizationRole.MEMBER)
        membership.status = MembershipStatus.SUSPENDED.value
        membership.joined_at = None
        db_session.flush()

        view = service.update_member(
            actor=employer,
            organization_id=organization.id,
            membership_id=membership.id,
            payload=MembershipUpdateRequest(status=MembershipStatus.ACTIVE),
        )
        assert view.membership.joined_at is not None

    def test_a_suspended_owner_does_not_count_towards_the_minimum(
        self, service, db_session, employer, worker
    ) -> None:
        """A suspended owner cannot act, so it cannot be the one that remains."""
        organization = _make_organization(db_session, employer)
        other = _add_membership(db_session, organization, worker, OrganizationRole.OWNER)
        owner_membership = db_session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id,
                OrganizationMembership.user_id == employer.id,
            )
        ).scalar_one()
        other.status = MembershipStatus.SUSPENDED.value
        db_session.flush()

        with pytest.raises(LastOwnerError):
            service.update_member(
                actor=employer,
                organization_id=organization.id,
                membership_id=owner_membership.id,
                payload=MembershipUpdateRequest(role=OrganizationRole.MEMBER),
            )

    def test_the_sole_owner_cannot_close_the_company(self, service, db_session, employer) -> None:
        organization = _make_organization(db_session, employer)
        with pytest.raises(LastOwnerError):
            service.delete(actor=employer, organization_id=organization.id)
        assert organization.deleted_at is None

    def test_a_second_owner_allows_the_company_to_close(
        self, service, db_session, employer, worker
    ) -> None:
        organization = _make_organization(db_session, employer)
        _add_membership(db_session, organization, worker, OrganizationRole.OWNER)
        service.delete(actor=employer, organization_id=organization.id)
        assert organization.deleted_at is not None
        assert organization.is_active is False

    def test_removal_records_the_membership_in_the_audit_trail(
        self, service, db_session, employer, worker, audit_rows
    ) -> None:
        organization = _make_organization(db_session, employer)
        membership = _add_membership(db_session, organization, worker, OrganizationRole.MEMBER)
        service.remove_member(
            actor=employer, organization_id=organization.id, membership_id=membership.id
        )
        rows = audit_rows(action=AuditAction.MEMBERSHIP_REMOVED.value)
        assert rows[-1].metadata_["membership_id"] == str(membership.id)
        assert rows[-1].metadata_["subject_user_id"] == str(worker.id)
        assert worker.email not in str(rows[-1].metadata_)


# --------------------------------------------------------------------------- #
# Contact-block validation                                                    #
# --------------------------------------------------------------------------- #
class TestContactBlockValidation:
    """The phone rules are the platform's, not one schema's."""

    @pytest.mark.parametrize(
        ("raw", "stored"),
        [
            ("0712345678", "0712345678"),
            ("+254712345678", "0712345678"),
            ("+254 712 345 678", "0712345678"),
            ("020-123-4567", "0201234567"),
            (None, None),
        ],
    )
    def test_accepts_kenyan_formats(self, raw: str | None, stored: str | None) -> None:
        assert normalise_kenyan_phone(raw) == stored

    @pytest.mark.parametrize(
        "raw", ["12345", "0712345678901", "not-a-number", "+447712345678", "012345678"]
    )
    def test_rejects_other_formats(self, raw: str) -> None:
        with pytest.raises(ValueError):
            normalise_kenyan_phone(raw)

    def test_the_rules_apply_to_an_update_as_well_as_a_create(self) -> None:
        with pytest.raises(PydanticValidationError):
            OrganizationUpdateRequest(contact_phone="12345")

    def test_only_http_and_https_links_are_accepted(self) -> None:
        assert OrganizationCreateRequest(name="Linked Ltd", website_url="https://a.example")
        for url in ("javascript:alert(1)", "ftp://a.example", "a.example"):
            with pytest.raises(PydanticValidationError):
                OrganizationCreateRequest(name="Unlinked Ltd", website_url=url)

    def test_an_explicit_null_skips_the_website_rule(self) -> None:
        request = OrganizationCreateRequest(name="Unlinked Ltd", website_url=None)
        assert request.website_url is None


# --------------------------------------------------------------------------- #
# Removal                                                                     #
# --------------------------------------------------------------------------- #
class TestRemoval:
    def test_a_member_who_is_not_an_owner_is_removed_freely(
        self, service, db_session, employer, worker
    ) -> None:
        organization = _make_organization(db_session, employer)
        membership = _add_membership(db_session, organization, worker, OrganizationRole.MEMBER)
        service.remove_member(
            actor=employer, organization_id=organization.id, membership_id=membership.id
        )
        remaining = db_session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id
            )
        ).scalars()
        assert [row.user_id for row in remaining] == [employer.id]

    def test_a_membership_id_from_no_company_at_all_is_not_found(
        self, service, db_session, employer
    ) -> None:
        organization = _make_organization(db_session, employer)
        with pytest.raises(MembershipNotFoundError):
            service.remove_member(
                actor=employer, organization_id=organization.id, membership_id=uuid.uuid4()
            )


# --------------------------------------------------------------------------- #
# Refusals are recorded durably                                               #
# --------------------------------------------------------------------------- #
class TestDeniedAudit:
    def test_a_cross_tenant_read_is_recorded_as_denied(
        self, service, db_session, employer, worker, audit_rows
    ) -> None:
        organization = _make_organization(db_session, employer)
        with pytest.raises(OrganizationNotFoundError):
            service.list_members(actor=worker, organization_id=organization.id)

        rows = audit_rows(outcome="DENIED")
        assert rows[-1].metadata_["reason"] == "NOT_AN_ACTIVE_ORGANIZATION_MEMBER"
        assert rows[-1].resource_id == organization.id
        assert rows[-1].actor_user_id == worker.id

    def test_a_refused_escalation_is_recorded_with_its_reason(
        self, service, db_session, employer, worker, audit_rows
    ) -> None:
        organization = _make_organization(db_session, employer)
        _add_membership(db_session, organization, worker, OrganizationRole.ADMIN)
        with pytest.raises(OrganizationRoleEscalationError):
            service.add_member(
                actor=worker,
                organization_id=organization.id,
                payload=MembershipCreateRequest(user_id=uuid.uuid4(), role=OrganizationRole.OWNER),
            )
        rows = audit_rows(action=AuditAction.MEMBERSHIP_ROLE_CHANGED.value, outcome="DENIED")
        assert rows[-1].metadata_["reason"] == "ORG_OWNERSHIP_GRANT_RESERVED"


# --------------------------------------------------------------------------- #
# Administrator surface                                                       #
# --------------------------------------------------------------------------- #
class TestAdministratorSurface:
    def test_the_role_is_re_asserted_in_the_service(
        self, service, db_session, employer, make_admin
    ) -> None:
        """The route dependency is not the only thing standing between them and us."""
        organization = _make_organization(db_session, employer)
        for call in (
            lambda: service.admin_get(actor=employer, organization_id=organization.id),
            lambda: service.admin_list(actor=employer),
            lambda: service.admin_delete(actor=employer, organization_id=organization.id),
            lambda: service.admin_update(
                actor=employer,
                organization_id=organization.id,
                payload=OrganizationAdminUpdateRequest(is_verified=True),
            ),
        ):
            with pytest.raises(InsufficientRoleError):
                call()
        assert organization.deleted_at is None

    def test_an_empty_administrator_patch_is_a_no_op(
        self, service, db_session, employer, make_admin
    ) -> None:
        organization = _make_organization(db_session, employer)
        view = service.admin_update(
            actor=make_admin(),
            organization_id=organization.id,
            payload=OrganizationAdminUpdateRequest(),
        )
        assert view.organization.is_verified is False

    def test_the_verification_mark_and_the_open_flag_are_administrator_only(
        self, service, db_session, employer, make_admin
    ) -> None:
        organization = _make_organization(db_session, employer)
        view = service.admin_update(
            actor=make_admin(),
            organization_id=organization.id,
            payload=OrganizationAdminUpdateRequest(is_verified=True, is_active=False),
        )
        assert view.organization.is_verified is True
        assert view.organization.is_active is False

    def test_closed_companies_are_hidden_from_the_default_listing(
        self, service, db_session, employer, make_admin
    ) -> None:
        live = _make_organization(db_session, employer, name="Live Ltd")
        paused = _make_organization(db_session, employer, name="Paused Ltd")
        paused.is_active = False
        closed = _make_organization(db_session, employer, name="Closed Ltd")
        closed.deleted_at = utcnow()
        db_session.flush()
        admin = make_admin()

        visible, total = service.admin_list(actor=admin)
        assert total == 2
        assert {view.organization.id for view in visible} == {live.id, paused.id}

        everything, total = service.admin_list(actor=admin, include_deleted=True)
        assert total == 3
        assert {view.organization.id for view in everything} == {
            live.id,
            paused.id,
            closed.id,
        }

        reopened, total = service.admin_list(actor=admin, is_active=False)
        assert [view.organization.id for view in reopened] == [paused.id]

        verified, total = service.admin_list(actor=admin, is_verified=True)
        assert (total, verified) == (0, [])

    def test_an_administrator_reads_a_closed_company(
        self, service, db_session, employer, make_admin
    ) -> None:
        organization = _make_organization(db_session, employer)
        service.admin_delete(actor=make_admin(), organization_id=organization.id)

        view = service.admin_get(actor=make_admin(), organization_id=organization.id)
        assert view.organization.deleted_at is not None

    def test_a_closed_company_is_not_editable(
        self, service, db_session, employer, make_admin
    ) -> None:
        organization = _make_organization(db_session, employer)
        service.admin_delete(actor=make_admin(), organization_id=organization.id)
        with pytest.raises(OrganizationNotFoundError):
            service.admin_update(
                actor=make_admin(),
                organization_id=organization.id,
                payload=OrganizationAdminUpdateRequest(is_verified=True),
            )

    def test_an_unknown_company_is_not_found(self, service, make_admin) -> None:
        with pytest.raises(OrganizationNotFoundError):
            service.admin_get(actor=make_admin(), organization_id=uuid.uuid4())
